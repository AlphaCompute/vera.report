import { performance } from 'node:perf_hooks';
import { createApplicationChannelIdentity, ApplicationChannelIdentity } from './application-channel-identity.js';
import { openChannelRequest, sealChannelResponse } from './confidential/channelMessage.js';
import { createSessionChallenges } from './session-challenges.js';
import type { SessionChallenges } from './session-challenges.js';

/** Session budget. The pool is larger than the host relay's admission pool, so
 * the host's per-client fairness is the binding limit; this is the backstop.
 * A session nobody has authenticated on is idle-expired quickly, so an anonymous
 * caller holding slots must keep paying for requests to keep them. A session that
 * carried a verified participant proof keeps a longer idle window, so one session
 * can serve a whole multi-range evidence download. */
export const SESSION_LIMITS = Object.freeze({
  capacity: 64,
  /** From open until the next request, while no participant proof has verified. */
  anonymousIdle: 15_000,
  /** Between requests after a participant proof verified on this session. */
  authenticatedIdle: 60_000,
  /** Bound on one in-flight request. */
  requestDeadline: 60_000,
  /** Absolute session lifetime and request count, regardless of activity. */
  maxLifetime: 10 * 60_000,
  maxRequests: 512,
});
const FAILURE = 'Confidential channel unavailable';
/** A call refused before any work because this nonce has no session ready for
 * it: `missing` (never opened here, expired or already closed) or `busy` (a
 * request is still running on it). The host already knows both from the frames
 * it relays, so naming them reveals nothing; it lets the relay answer "open a
 * new session" or "one request at a time" instead of reporting an outage.
 * Every other failure stays the generic FAILURE. */
export class ChannelSessionRejected extends Error {
  constructor(readonly session: 'missing' | 'busy') { super(FAILURE); }
}
export type ChannelDispatch = (body: Uint8Array, context: Readonly<{
  nonce: string; requestId: string; serverKeyId: string; requestDigest: string; signal: AbortSignal;
  /** Called by the dispatcher after a participant proof bound to this session
   * verified and its single-use challenge was consumed. */
  authenticated?: () => void;
  /** Enclave-memory, single-use participant challenges issued inside THIS
   * session only (see session-challenges.ts). The host never holds them. */
  challenges: SessionChallenges;
}>) => Promise<Uint8Array>;
type Entry = { state: 'generating' | 'ready' | 'consuming'; expires: number; created: number;
  identity?: ApplicationChannelIdentity; timer?: ReturnType<typeof setTimeout>; abort: AbortController;
  authenticated: boolean; requests: number; seen: Set<string>; challenges: SessionChallenges };

/** Production constructor: neither attestor nor clock is request-selectable.
 * Dispatch is measured enclave-local code and MUST enforce principal, current
 * case policy and release authority. There is no default echo/decrypt handler. */
export function createApplicationChannelSessions(dispatch: ChannelDispatch) {
  return createSessionCore(dispatch, createApplicationChannelIdentity, () => performance.now());
}

/** Internal composition seam for deterministic tests, never a route option. */
export function createSessionCore(dispatch: ChannelDispatch,
  identityFactory: typeof createApplicationChannelIdentity, clock: () => number,
  overrides: Partial<typeof SESSION_LIMITS> = {}) {
  const limits = { ...SESSION_LIMITS, ...overrides };
  const entries = new Map<string, Entry>();
  let closed = false, previous = -Infinity;
  function now(): number {
    const time = clock();
    if (!Number.isFinite(time) || time < 0 || time < previous) throw new Error(FAILURE);
    previous = time; return time;
  }
  function remove(nonce: string, entry: Entry) {
    if (entries.get(nonce) === entry) entries.delete(nonce);
    clearTimeout(entry.timer); entry.identity?.close(); entry.identity = undefined;
    entry.seen.clear(); entry.challenges.clear();
    entry.abort.abort();
  }
  function schedule(nonce: string, entry: Entry, time: number) {
    clearTimeout(entry.timer);
    entry.timer = setTimeout(() => {
      entry.abort.abort();
      if (entry.state === 'ready') remove(nonce, entry);
    }, Math.max(0, entry.expires - time));
    entry.timer.unref();
  }
  function valid(entry: Entry) {
    if (closed || entry.abort.signal.aborted || now() >= entry.expires) throw new Error(FAILURE);
  }
  function challenge(nonce: string) {
    if (typeof nonce !== 'string' || !/^[0-9a-f]{64}$/.test(nonce)) throw new Error(FAILURE);
  }
  function sweep(time: number) {
    for (const [nonce, entry] of entries) if (time >= entry.expires) {
      entry.abort.abort();
      // Keep in-flight work admitted until it settles: expiry must not let an
      // attacker start unbounded generators/handlers by cycling expired slots.
      if (entry.state === 'ready') remove(nonce, entry);
    }
  }
  return {
    async open(nonce: string) {
      let entry: Entry | undefined;
      try {
        challenge(nonce); const time = now(); sweep(time);
        if (closed || entries.has(nonce) || entries.size >= limits.capacity) throw new Error(FAILURE);
        entry = { state: 'generating', created: time, expires: time + limits.requestDeadline,
          abort: new AbortController(), authenticated: false, requests: 0, seen: new Set(),
          challenges: createSessionChallenges() };
        entries.set(nonce, entry); // Reserve synchronously, before key generation.
        schedule(nonce, entry, time);
        const identity = await identityFactory(nonce);
        entry.identity = identity;
        valid(entry);
        if (identity.evidence.nonce !== nonce) throw new Error(FAILURE);
        entry.state = 'ready';
        const opened = now();
        entry.expires = opened + limits.anonymousIdle;
        schedule(nonce, entry, opened);
        return { ...identity.evidence }; // No credential object reaches the host.
      } catch {
        if (entry) remove(nonce, entry);
        throw new Error(FAILURE);
      }
    },
    /** One request at a time per session. Each request has its own reply key and
     * request ID; a replayed ciphertext or request ID closes the session. Any
     * failure closes the session, so a caller never learns partial state.
     * `last` (a relay-visible hint) closes the session after this reply. */
    async execute(nonce: string, ciphertext: string, options: { last?: boolean } = {}): Promise<string> {
      let active: Entry | undefined, body: Uint8Array | undefined, response: Uint8Array | undefined, keep = false;
      try {
        challenge(nonce); const time = now(); sweep(time);
        const entry = entries.get(nonce);
        if (!entry) throw new ChannelSessionRejected('missing');
        if (entry.state !== 'ready') throw new ChannelSessionRejected('busy');
        valid(entry);
        entry.state = 'consuming'; active = entry; // Claim before any await.
        entry.requests++;
        entry.expires = Math.min(time + limits.requestDeadline, entry.created + limits.maxLifetime);
        schedule(nonce, entry, time);
        const identity = entry.identity!;
        const request = await openChannelRequest(ciphertext, nonce, identity.getPrivateKey());
        body = request.body;
        valid(entry);
        const { requestId, requestDigest } = request.binding;
        if (entry.seen.has(requestId) || entry.seen.has(requestDigest)) throw new Error(FAILURE);
        entry.seen.add(requestId); entry.seen.add(requestDigest);
        response = await dispatch(body, Object.freeze({ ...request.binding, signal: entry.abort.signal,
          authenticated: () => { entry.authenticated = true; }, challenges: entry.challenges }));
        valid(entry);
        const result = await sealChannelResponse(request, response, identity.getPrivateKey());
        valid(entry);
        const finished = now();
        const idle = entry.authenticated ? limits.authenticatedIdle : limits.anonymousIdle;
        const expires = Math.min(finished + idle, entry.created + limits.maxLifetime);
        keep = options.last !== true && entry.requests < limits.maxRequests && expires > finished;
        if (keep) {
          entry.expires = expires; entry.state = 'ready';
          schedule(nonce, entry, finished);
        }
        return result;
      } catch (error) { throw error instanceof ChannelSessionRejected ? error : new Error(FAILURE); }
      finally {
        body?.fill(0);
        if (response instanceof Uint8Array) response.fill(0);
        if (active && !keep) remove(nonce, active);
      }
    },
    /** Host availability bookkeeping only; an error from a duplicate call must
     * not claim that an independently running session has completed. */
    hasPendingSession(nonce: string): boolean { return entries.has(nonce); },
    /** Close a quiescent session at the relay's request. Initial verification
     * and a freshly issued challenge's follow-up are part of an active exchange,
     * even between frames. Existing idle/lifetime deadlines still reclaim them. */
    release(nonce: string): boolean {
      sweep(now());
      const entry = entries.get(nonce);
      if (!entry) return true;
      if (entry.state !== 'ready' || entry.requests === 0 || entry.challenges.hasPendingFollowup()) return false;
      remove(nonce, entry);
      return true;
    },
    close(): void {
      closed = true;
      for (const [nonce, entry] of entries) remove(nonce, entry);
    },
  };
}
