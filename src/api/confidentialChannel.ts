import { CHANNEL_ADMISSION, createChannelAdmission } from '../utils/confidentialAdmission';
import net from 'node:net';
import express, { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { requestRateLimitKey } from '../utils/proxyRateLimit';
import { sharedRateLimitStore } from '../utils/mongoRateLimitStore';
import { confidentialBodyErrors, confidentialRequestGuard } from '../middleware/confidentialRequestGuard';
import type { ChannelOutcome } from '../utils/confidentialChannelOutcomes';

/** Host relay for the attested confidential-case channel. It forwards a browser
 * nonce and opaque ciphertext to the enclave (via the local vsock bridge) and
 * returns the enclave's evidence/ciphertext unchanged. It cannot read, alter
 * undetectably, or originate private operations: the browser verifies the NSM
 * document and every reply is encrypted to the browser's ephemeral key. */
/** The enclave frame server (enclave/src/confidential-server.ts) rejects any
 * frame over 1 MiB, including the `{"op":"call","nonce":…,"ciphertext":…}`
 * JSON envelope. Accept only ciphertext that still fits once framed. */
export const ENCLAVE_MAX_FRAME = 1024 * 1024;
export const CALL_ENVELOPE_RESERVE = 1024;
export const MAX_CIPHERTEXT = ENCLAVE_MAX_FRAME - CALL_ENVELOPE_RESERVE;
/** Largest JSON body a call can need: the ciphertext, a 64-hex nonce and framing.
 * Parsed here, before the application's general 10 MB parser (server.ts skips
 * this family), so an oversized body is refused while streaming. */
export const CHANNEL_JSON_LIMIT = MAX_CIPHERTEXT + 1024;
/** Enclave calls in flight from this API process. Each open costs the enclave an
 * NSM attestation and key generation; excess load is shed with a retryable 503
 * instead of queueing unbounded sockets toward the enclave. */
export const CHANNEL_MAX_IN_FLIGHT = 64;

export type EnclaveChannelTransport = (request: unknown) => Promise<unknown>;

export function tcpEnclaveTransport(port = 5004, host = process.env.ENCLAVE_HOST || '127.0.0.1', timeoutMs = 20_000): EnclaveChannelTransport {
  return framedTransport(() => net.connect(port, host), timeoutMs);
}

/** Same framing over a host Unix socket bridged to vsock 5004. Used by the
 * bridge-mode API task, whose loopback is not the parent instance's loopback. */
export function socketEnclaveTransport(path: string, timeoutMs = 20_000): EnclaveChannelTransport {
  if (typeof path !== 'string' || !path.startsWith('/')) throw new Error('Enclave socket path must be absolute');
  return framedTransport(() => net.connect(path), timeoutMs);
}

function framedTransport(connect: () => net.Socket, timeoutMs: number): EnclaveChannelTransport {
  return request => new Promise((resolve, reject) => {
    const socket = connect();
    const payload = Buffer.from(JSON.stringify(request)), header = Buffer.alloc(4);
    header.writeUInt32BE(payload.length, 0);
    let buffer = Buffer.alloc(0);
    const timer = setTimeout(() => { socket.destroy(); reject(new Error('timeout')); }, timeoutMs);
    socket.on('data', (chunk: Buffer) => {
      buffer = Buffer.concat([buffer, chunk]);
      if (buffer.length > ENCLAVE_MAX_FRAME * 2) { socket.destroy(); reject(new Error('oversized')); }
    });
    socket.on('end', () => {
      clearTimeout(timer);
      try {
        if (buffer.length < 4 || buffer.readUInt32BE(0) !== buffer.length - 4) throw new Error('frame');
        resolve(JSON.parse(buffer.subarray(4).toString('utf8')));
      } catch (error) { reject(error); }
    });
    socket.on('error', error => { clearTimeout(timer); reject(error); });
    socket.write(Buffer.concat([header, payload]));
  });
}

/** `maxPerMinute` exists for in-process test harnesses that drive many channel
 * operations from one address; production uses the default. */
export function createConfidentialChannelRouter(transport: EnclaveChannelTransport, options: {
  maxPerMinute?: number; maxInFlight?: number; allowedOrigins?: readonly string[]; admissionClock?: () => number;
  /** Counts only (src/utils/confidentialChannelOutcomes.ts); never request data. */
  onOutcome?: (outcome: ChannelOutcome) => void;
} = {}) {
  const router = Router();
  const admission = createChannelAdmission(options.admissionClock);
  const guard = confidentialRequestGuard('application/json', options.allowedOrigins);
  const parse = express.json({ limit: CHANNEL_JSON_LIMIT, strict: true, type: 'application/json' });
  const maxInFlight = options.maxInFlight ?? CHANNEL_MAX_IN_FLIGHT;
  const outcome = options.onOutcome ?? (() => {});
  let inFlight = 0;
  const shed = Symbol('shed-before-transport');
  const relay = async (res: import('express').Response, request: unknown): Promise<Record<string, unknown> | typeof shed> => {
    if (inFlight >= maxInFlight) {
      if (!res.headersSent && !res.writableEnded && !res.destroyed) {
        res.setHeader('Retry-After', '2');
        res.status(503).json({ error: 'Secure connection busy, please try again shortly.' });
      }
      return shed;
    }
    inFlight++;
    try { return await transport(request) as Record<string, unknown>; } finally { inFlight--; }
  };
  // A maximum-size object needs 128 ranges on one reused session: one open and
  // about one call per range (reads sign challenges fetched in batches of 8 in
  // that same session). Bound a burst while allowing one complete evidence read
  // with room for retries.
  const limiter = rateLimit({ keyGenerator: requestRateLimitKey, store: sharedRateLimitStore('confidentialChannel'), windowMs: 60_000, max: options.maxPerMinute ?? 600,
    standardHeaders: true, legacyHeaders: false, message: { error: 'Too many requests, please try again later.' },
    // Same response as the default handler; also counted, so the outcome
    // totals reconcile with the load balancer's request and status counts.
    handler: (req, res, _next, limit) => {
      outcome(req.path.endsWith('/open') ? 'open_rate_limited' : 'call_rate_limited');
      res.status(limit.statusCode).send(limit.message);
    } });
  const writable = (res: import('express').Response) => !res.headersSent && !res.writableEnded && !res.destroyed;
  const unavailable = (res: import('express').Response) => {
    if (writable(res)) res.status(503).json({ error: 'Secure connection unavailable' });
  };
  /** The enclave refused a call before doing any work (ChannelSessionRejected in
   * enclave/src/application-channel-sessions.ts). These are the client's to
   * resolve, not outages: a missing session needs a new open, a busy one takes
   * one request at a time. Browsers already treat any non-throttle HTTP error
   * here as "unavailable" and retry a reused session on a fresh one, so only
   * the status changes. An enclave that does not label refusals keeps 503. */
  const refused = (res: import('express').Response, session: unknown): ChannelOutcome => {
    if (session === 'missing') {
      if (writable(res)) res.status(410).json({ error: 'Secure session expired' });
      return 'call_session_missing';
    }
    if (session === 'busy') {
      if (writable(res)) res.status(409).json({ error: 'Secure session busy' });
      return 'call_session_busy';
    }
    unavailable(res);
    return 'call_enclave_error';
  };
  router.post('/channel/open', guard, limiter, parse, async (req, res) => {
    if (!writable(res)) return;
    res.setHeader('Cache-Control', 'no-store');
    const body = req.body;
    if (!body || typeof body !== 'object' || Object.keys(body).join(',') !== 'nonce' ||
        typeof body.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(body.nonce)) {
      res.status(400).json({ error: 'Invalid request' }); return;
    }
    const key = requestRateLimitKey(req);
    let admitted = admission.reserve(body.nonce, key);
    if (!admitted) {
      // At this client's own cap: close its least recently used idle session in
      // the enclave (only an idle one; the enclave refuses otherwise) and reuse
      // the slot. The client's cap and the global pool never grow.
      const victim = admission.idleVictim(key);
      if (victim) {
        try {
          const closed = await relay(res, { op: 'close', nonce: victim });
          if (closed === shed) { admission.restoreVictim(victim, key); outcome('open_shed'); return; }
          if (closed?.closed === true) { admission.complete(victim, key); admitted = admission.reserve(body.nonce, key); }
          else if (closed?.closed === false) admission.restoreVictim(victim, key);
        } catch { /* Unconfirmed: keep the victim's lease until it expires. */ }
      }
    }
    if (!admitted) {
      if (!writable(res)) return;
      res.setHeader('Retry-After', String(Math.ceil(CHANNEL_ADMISSION.openLease / 1000)));
      res.status(429).json({ error: 'Secure connection busy, please try again later.' });
      outcome('open_throttled'); return;
    }
    // A timeout/abort is ambiguous: retain the lease until expiry because the
    // enclave may still be generating or consuming this session.
    try {
      const reply = await relay(res, { op: 'open', nonce: body.nonce });
      // Shed before reaching the enclave: no session exists, so free the lease.
      if (reply === shed) { admission.complete(body.nonce, key); outcome('open_shed'); return; }
      if (typeof reply?.document !== 'string' || typeof reply?.publicKey !== 'string') {
        unavailable(res); outcome('open_enclave_error'); return;
      }
      admission.opened(body.nonce, key);
      if (writable(res)) res.json({ document: reply.document, publicKey: reply.publicKey });
      outcome('open_ok');
    } catch { unavailable(res); outcome('open_transport_error'); }
  });
  router.post('/channel/call', guard, limiter, parse, async (req, res) => {
    if (!writable(res)) return;
    res.setHeader('Cache-Control', 'no-store');
    const body = req.body;
    const fields = body && typeof body === 'object' ? Object.keys(body).sort().join(',') : '';
    if (!body || typeof body !== 'object' || (fields !== 'ciphertext,nonce' && !(fields === 'ciphertext,last,nonce' && body.last === true)) ||
        typeof body.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(body.nonce) ||
        typeof body.ciphertext !== 'string' || !body.ciphertext.length || body.ciphertext.length > MAX_CIPHERTEXT) {
      res.status(400).json({ error: 'Invalid request' }); return;
    }
    const frame = body.last === true ? { op: 'call', nonce: body.nonce, ciphertext: body.ciphertext, last: true }
      : { op: 'call', nonce: body.nonce, ciphertext: body.ciphertext };
    // Escaping or multibyte text can exceed the frame limit even when the
    // ciphertext's JavaScript character count is below its ASCII armor cap.
    if (Buffer.byteLength(JSON.stringify(frame), 'utf8') > ENCLAVE_MAX_FRAME) {
      res.status(413).json({ error: 'Request too large' }); return;
    }
    const key = requestRateLimitKey(req);
    admission.begin(body.nonce, key);
    try {
      const reply = await relay(res, frame);
      if (reply === shed) { outcome('call_shed'); return; }
      if (reply?.sessionClosed === true) admission.complete(body.nonce, key);
      if (typeof reply?.ciphertext !== 'string') { outcome(refused(res, reply?.session)); return; }
      if (reply.sessionOpen === true) admission.renew(body.nonce, key); else admission.complete(body.nonce, key);
      if (writable(res)) res.json({ ciphertext: reply.ciphertext });
      outcome('call_ok');
    } catch { unavailable(res); outcome('call_transport_error'); }
  });
  router.use('/channel', confidentialBodyErrors);
  return router;
}
