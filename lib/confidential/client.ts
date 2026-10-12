import { ConfidentialRateLimitError } from './readRetry';
import { assertReleaseNotWithdrawn, fetchReleaseWithdrawals, isReleasePaused } from './releaseWithdrawals';
import { recordVerification } from './verificationRecord';
import { attestedTimeMark, recordAttestedTime, trustedNow, trustedTime } from './attestedTime';
import { readKey } from '../../enclave/src/confidential/pgp';
import type { PrivateKey } from '../../enclave/src/confidential/pgp';
import { verifyApplicationAttestation } from '../../enclave/src/confidential/attestation';
import { attestationTimeFits, attestationTimestamp } from '../../enclave/src/confidential/attestationEvidence';
import { readReleaseManifest } from '../../enclave/src/confidential/releaseManifest';
import { ChannelClockError, sealChannelRequest } from '../../enclave/src/confidential/channelMessage';
import { caseRecipientKeyId } from '../../enclave/src/confidential/caseObject';
import { signParticipantRequest } from '../../enclave/src/confidential/participantRequest';
import type { ParticipantOperation } from '../../enclave/src/confidential/participantRequest';
import { EvidenceChangedError, chunkCiphertextLength, parseChunkedIndex } from '../../enclave/src/confidential/caseChunks';
import type { SealedChunkedObject } from '../../enclave/src/confidential/caseChunks';

/** Browser client for the attested confidential-case channel.
 * The host only relays opaque bytes: it opens a session for a browser nonce and
 * returns the enclave's NSM document and ephemeral channel key; the browser
 * verifies the fixed AWS root, freshness and the expected release PCRs before
 * encrypting anything. There is NO plaintext or legacy fallback: every failure
 * surfaces as `ConfidentialUnavailableError` (with a `reason`) and the caller keeps the draft.
 */
/** Why a confidential operation failed, as far as this device can tell.
 * - `verification`: the service did not prove it runs the approved release, or
 *   its encrypted reply did not check out. This is the case that can mean
 *   interception or a substituted backend.
 * - `busy`: the relay throttled or shed load before forwarding.
 * - `offline`: the relay could not be reached (no network, DNS, blocked request).
 * - `unavailable`: the relay answered with an HTTP error (maintenance, overload).
 * - `clock`: attestation or a channel key exceeds the supported clock skew,
 *   so the failure is most likely the device clock. */
export type ChannelFailureReason = 'verification' | 'busy' | 'offline' | 'unavailable' | 'clock';
export type ConfidentialFailureReason = ChannelFailureReason;
const FAILURE_MESSAGES: Record<ChannelFailureReason, string> = {
  // A verification, network or relay failure can happen after the enclave
  // already applied a change, so these never claim that nothing was sent.
  verification: 'The secure connection could not be verified. VERA\'s secure service did not prove it runs the approved software. ' +
    'If you were making a change, it may have completed. Check the report before trying again. If this keeps happening, ' +
    'your connection may be intercepted; try another network.',
  // HTTP status is not authenticated. A host can report throttling after a commit,
  // and earlier steps may already have sent data; never promise a mutation did not happen.
  busy: 'The secure connection is busy right now. If you were making a change, it may have completed. Check the report before trying again.',
  offline: 'The secure connection could not be reached. Check your internet connection. If you were making a change, it may have completed. Check the report before trying again.',
  unavailable: 'The secure connection is temporarily unavailable. If you were making a change, it may have completed. Check the report before trying again.',
  clock: 'The secure connection could not be verified because this device\'s date and time look wrong. ' +
    'Set your date and time to update automatically, then try again.',
};
/** Every message starts with "The secure connection" (screens key on that).
 * A failed attestation or decryption always remains `verification`. `busy`,
 * `offline` and `unavailable` are unauthenticated HTTP/network availability hints,
 * never proof that a mutation was not applied or that a host behaved honestly.
 * `clock` is an attestation or channel key time outside the supported clock
 * tolerance. Messages never quote internal error text. */
export class ConfidentialUnavailableError extends Error {
  constructor(readonly reason: ChannelFailureReason = 'verification') {
    super(FAILURE_MESSAGES[reason]);
    this.name = 'ConfidentialUnavailableError';
  }
}
/** The relay answered with an HTTP error (not a throttle). */
export class RelayHttpError extends Error {
  constructor(readonly status: number) { super('Relay request failed'); }
}
/** The request never got an HTTP answer (offline, DNS, connection reset). */
export class RelayNetworkError extends Error {
  constructor() { super('Relay unreachable'); }
}

/** Map any failure of a channel operation to the one error screens show. Keeps
 * the most specific known reason; never carries the underlying message (it could
 * quote ciphertext, identifiers or keys). */
export function channelFailure(error: unknown): ConfidentialUnavailableError {
  if (error instanceof ConfidentialUnavailableError) return error;
  if (error instanceof ChannelClockError) return new ConfidentialUnavailableError('clock');
  if (error instanceof ConfidentialRateLimitError) return new ConfidentialUnavailableError('busy');
  if (error instanceof RelayNetworkError) return new ConfidentialUnavailableError('offline');
  if (error instanceof RelayHttpError) return new ConfidentialUnavailableError('unavailable');
  return new ConfidentialUnavailableError('verification');
}

/** Attested enclave time (hole 8): signing uses `trustedTime(deviceNow)`,
 * every expiry and validity decision uses `trustedNow()`. See attestedTime.ts. */
export { hasAttestedTime, resetTrustedTime, trustedNow, trustedTime } from './attestedTime';
/** An evidence upload stopped part-way (connection lost, relay busy for too long).
 * Chunks already sent are kept; calling the same upload again resumes it. */
export class ConfidentialUploadInterruptedError extends Error {
  constructor() { super('The upload was interrupted. Nothing has been submitted yet. Check your connection, then resume the upload.'); }
}
/** Wraps any failure as unavailable, except a paused (withdrawn) release, which
 * callers must show differently: retrying will not help and nothing moves on. */
export { isReleasePaused };
export function unavailable(error: unknown): Error {
  return isReleasePaused(error) ? error : channelFailure(error);
}
export const CONFIDENTIAL_AUDIENCE = 'vera-confidential-cases';
export const CHANNEL_BODY_LIMIT = 128 * 1024;

export type ChannelRelay = {
  /** Upload participant-encrypted object ciphertext for staging; returns its SHA-256. */
  stage(ciphertext: string): Promise<string>;
  /** Upload one encrypted evidence chunk for staging; returns its SHA-256. */
  stageChunk(chunk: Uint8Array): Promise<string>;
  /** Host relay: create an enclave session for this fresh browser nonce. */
  open(nonce: string): Promise<{ document: Uint8Array; publicKey: Uint8Array }>;
  /** Host relay: forward sealed request ciphertext, return sealed reply ciphertext.
   * `last` asks the enclave to close the session after this reply (an
   * availability hint only: the host could add or drop it, and can already
   * refuse service). */
  call(nonce: string, ciphertext: string, last?: boolean, signal?: AbortSignal): Promise<string>;
  /** Signed release withdrawal list from the host, or null when none is published. */
  withdrawals?(): Promise<string | null>;
};

function hex(bytes: Uint8Array): string { return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join(''); }
export function base64(bytes: Uint8Array): string {
  let text = '';
  for (let index = 0; index < bytes.length; index += 0x8000) text += String.fromCharCode(...bytes.subarray(index, index + 0x8000));
  return btoa(text);
}
function unbase64(value: unknown, max: number): Uint8Array {
  if (typeof value !== 'string' || value.length > Math.ceil(max / 3) * 4) throw new Error();
  const bytes = Uint8Array.from(atob(value), char => char.charCodeAt(0));
  if (bytes.length > max || base64(bytes) !== value) throw new Error();
  return bytes;
}

/** 429 is a quota; a 503 that carries Retry-After is the relay shedding load
 * (enclave in-flight cap, staging byte budget). Both are retryable "busy", never
 * an attestation failure. A bare 503 means the secure service is unavailable. */
export function throwIfThrottled(response: Pick<Response, 'status' | 'headers'>): void {
  const retryAfter = response.headers.get('Retry-After');
  if (response.status === 429 || (response.status === 503 && retryAfter !== null)) throw new ConfidentialRateLimitError(retryAfter);
}

/** Bound unauthenticated relay bytes before parsing JSON. One deadline covers
 * both headers and the complete body, including a stream that never closes. */
async function relayFetch(url: string, init: RequestInit, maxBytes: number, signal?: AbortSignal): Promise<Pick<Response, 'status' | 'json'>> {
  signal?.throwIfAborted();
  // A browser that knows it is offline never reached VERA's relay.
  if (typeof navigator !== 'undefined' && navigator.onLine === false) throw new RelayNetworkError();
  const controller = new AbortController();
  let response: Response | undefined, reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let abort = () => {};
  const deadline = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => { controller.abort(); reject(new RelayNetworkError()); }, 60_000);
    abort = () => { controller.abort(); reject(signal!.reason); };
    signal?.addEventListener('abort', abort, { once: true });
  });
  const read = async () => {
    try { response = await fetch(url, { ...init, signal: controller.signal, referrerPolicy: 'no-referrer' }); }
    catch { throw new RelayNetworkError(); }
    if (controller.signal.aborted) {
      void response.body?.cancel().catch(() => undefined);
      throw new RelayNetworkError();
    }
    throwIfThrottled(response);
    if (!response.ok || !response.body) throw new RelayHttpError(response.status);
    const declared = response.headers.get('content-length');
    if (declared !== null && /^\d+$/.test(declared) && Number(declared) > maxBytes) throw new RelayHttpError(response.status);
    reader = response.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > maxBytes) throw new RelayHttpError(response.status);
      chunks.push(value);
    }
    const bytes = new Uint8Array(size);
    let offset = 0;
    for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
    return { status: response.status, json: async () => JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes)) };
  };
  try { return await Promise.race([read(), deadline]); }
  finally {
    clearTimeout(timer);
    signal?.removeEventListener('abort', abort);
    // Never wait on cancellation of an untrusted stream to settle the caller.
    if (reader) void reader.cancel().catch(() => undefined);
    else void response?.body?.cancel().catch(() => undefined);
    controller.abort();
  }
}

/** Brief waits before retrying a throttled session open. The relay holds at
 * most a few session leases per client address, and one page can start several
 * reads at once (a portal load checks membership, the shared list, the
 * directory and request statuses together). Leases turn over within seconds as
 * those calls finish, so the open is retried briefly instead of failing the
 * view. Opening sends nothing private and a throttled open reserves no session,
 * so the same fresh nonce is reused. Bounded: about 8 seconds in total. */
export const OPEN_RETRY_DELAYS_MS = [400, 800, 1600, 2400, 3200] as const;
export async function openWithRetry<T>(attempt: () => Promise<T>,
  wait: (ms: number) => Promise<void> = ms => new Promise(resolve => setTimeout(resolve, ms))): Promise<T> {
  for (let index = 0; ; index++) {
    try { return await attempt(); } catch (error) {
      if (!(error instanceof ConfidentialRateLimitError) || index >= OPEN_RETRY_DELAYS_MS.length) throw error;
      await wait(Math.min(error.delayMs, OPEN_RETRY_DELAYS_MS[index] * (0.75 + Math.random() / 2)));
    }
  }
}

/** Same-origin fetch relay. Endpoints are deliberately separate from `/api/whistleblower`. */
export function fetchRelay(base = '/api/confidential/channel', stagingUrl = '/api/confidential/objects',
  chunkUrl = stagingUrl.replace(/objects$/, 'chunks')): ChannelRelay {
  return {
    async stageChunk(chunk) {
      const response = await relayFetch(chunkUrl, { method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { 'Content-Type': 'application/vnd.vera.case-chunk+base64' }, body: base64(chunk) }, 1024);
      const value = await response.json().catch(() => null);
      if (typeof value?.digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.digest)) throw new RelayHttpError(response.status);
      return value.digest;
    },
    async stage(ciphertext) {
      const response = await relayFetch(stagingUrl, { method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { 'Content-Type': 'application/pgp-encrypted' }, body: ciphertext }, 1024);
      const value = await response.json();
      if (typeof value?.digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.digest)) throw new ConfidentialUnavailableError();
      return value.digest;
    },
    async open(nonce) {
      const response = await openWithRetry(() => relayFetch(`${base}/open`, { method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ nonce }) }, 32 * 1024));
      // A captive portal or error page is not evidence at all, so it is reported as
      // unavailability (a host able to do this could equally answer 503). Anything
      // shaped like evidence is judged by the attestation check.
      const value = await response.json().catch(() => null);
      try { return { document: unbase64(value?.document, 16384), publicKey: unbase64(value?.publicKey, 1024) }; }
      catch { throw new RelayHttpError(response.status); }
    },
    async call(nonce, ciphertext, last, signal) {
      // Channel replies permit 1536 KiB of armored ciphertext; leave room for
      // JSON framing and escaped armor line endings (including evidence chunks).
      const response = await relayFetch(`${base}/call`, { method: 'POST', cache: 'no-store', credentials: 'omit',
        headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(last ? { nonce, ciphertext, last: true } : { nonce, ciphertext }) }, 2 * 1024 * 1024, signal);
      const value = await response.json();
      if (typeof value?.ciphertext !== 'string') throw new ConfidentialUnavailableError();
      return value.ciphertext;
    },
    withdrawals: fetchReleaseWithdrawals,
  };
}

/** One verified session: PCRs come from the release manifest the participant is
 * approving (bundled with this build, or the owner's signed approval), never
 * from the relay's response. */
export async function verifiedSession(relay: ChannelRelay, releaseManifest: string, now?: number): Promise<VerifiedChannelSession> {
  // Verification time is read after the relay answers, not when the caller
  // started: a slow open or a long flow must not age a fresh quote.
  const clock = callerClock(now);
  const nonceBytes = globalThis.crypto.getRandomValues(new Uint8Array(32)), nonce = hex(nonceBytes);
  const { manifest, digest } = await readReleaseManifest(releaseManifest);
  // A withdrawn (or unconfirmed, when checks are pinned) release is paused
  // before the relay learns anything about this session.
  await assertReleaseNotWithdrawn(digest, trustedNow(), relay.withdrawals);
  const decode = (value: string) => Uint8Array.from(value.match(/../g)!, pair => parseInt(pair, 16));
  const expectedPcrs = new Map([[0, decode(manifest.measurements.pcr0)], [1, decode(manifest.measurements.pcr1)],
    [2, decode(manifest.measurements.pcr2)]]);
  const startedAt = attestedTimeMark();
  const evidence = await relay.open(nonce);
  let verified: Awaited<ReturnType<typeof verifyApplicationAttestation>>;
  const checkedAt = clock();
  try {
    verified = await verifyApplicationAttestation(evidence.document, evidence.publicKey,
      { nonce: nonceBytes, expectedPcrs, now: checkedAt });
  } catch {
    // Diagnosis only: the unauthenticated timestamp decides which message to
    // show, never whether to trust the session.
    const claimed = attestationTimestamp(evidence.document);
    throw new ConfidentialUnavailableError(claimed !== null && !attestationTimeFits(claimed, checkedAt) ? 'clock' : 'verification');
  }
  recordAttestedTime(verified.timestamp, startedAt);
  // The check above ran on this device's clock when no session had verified
  // yet; repeat it on attested time, so a device clock set back cannot keep an
  // expired withdrawal list (one that omits a later withdrawal) current.
  await assertReleaseNotWithdrawn(digest, trustedNow(), relay.withdrawals);
  const serverKey = await readKey({ binaryKey: verified.publicKey });
  const session = { nonce, serverKey, serverKeyId: await caseRecipientKeyId(serverKey) };
  recordVerification({ releaseDigest: digest, sourceCommit: manifest.sourceCommit, sourceRepository: manifest.sourceRepository,
    verifiedAt: trustedNow() });
  return session;
}

/** One verified session only to learn attested enclave time before signing
 * anything (for example a new report's first checkpoint). */
export async function synchronizeTrustedTime(relay: ChannelRelay, releaseManifest: string, now: number): Promise<void> {
  try {
    const session = await verifiedSession(relay, releaseManifest, now);
    // Consume the one-use session so it does not hold an enclave slot and relay
    // lease until expiry. A challenge is the cheapest operation with a reply.
    const reply = await exchange(relay, session, { operation: 'case.challenge' }) as { challenge?: unknown };
    if (typeof reply?.challenge !== 'string' || !/^[a-f0-9]{64}$/.test(reply.challenge)) throw new Error();
  } catch (error) { throw unavailable(error); }
}

export type VerifiedChannelSession = {
  nonce: string;
  serverKey: Awaited<ReturnType<typeof readKey>>;
  serverKeyId: string;
};

/** One encrypted request/reply on a verified session. Callers wrap failures.
 * By default this is the session's last request, so the enclave and relay free
 * the slot at once; `ChannelSessions` keeps a session open for reuse. */
export async function exchange(relay: ChannelRelay, session: VerifiedChannelSession, request: unknown,
  last = true, signal?: AbortSignal): Promise<unknown> {
  signal?.throwIfAborted();
  const body = new TextEncoder().encode(JSON.stringify(request));
  let pending: Awaited<ReturnType<typeof sealChannelRequest>>;
  try { pending = await sealChannelRequest(session.serverKey, session.nonce, body); } finally { body.fill(0); }
  signal?.throwIfAborted();
  const ciphertext = await relay.call(session.nonce, pending.ciphertext, last, signal);
  signal?.throwIfAborted();
  const reply = await pending.openResponse(ciphertext);
  try { return JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(reply)); } finally { reply.fill(0); }
}

/** Client view of the enclave's session reuse policy (SESSION_LIMITS in
 * enclave/src/application-channel-sessions.ts), with margins for relay latency
 * and clock drift. A session whose enclave copy has already expired only costs
 * one failed challenge, which is retried on a fresh session. */
const REUSE = { anonymousIdle: 8_000, authenticatedIdle: 45_000, maxLifetime: 9 * 60_000, maxRequests: 480 };
/** Challenges requested per batch for reads (the enclave issues at most 8 per
 * request and holds at most 16 unused per session; session-challenges.ts). */
export const CHALLENGE_BATCH = 4;
const MAX_CHALLENGE_BATCH = 8;
/** Stocked challenges are spent only well inside the enclave's 120 s lifetime. */
const CHALLENGE_STOCK_MS = 60_000;
type ChallengeOperation = 'case.challenge' | 'legal.challenge';
type Held = { session: VerifiedChannelSession; openedAt: number; lastUsed: number; uses: number; authenticated: boolean;
  /** Unused single-use challenges issued inside THIS session (memory only). */
  challenges: string[]; challengesAt: number };
/** Per-run view of the held session's challenge stock and reuse state. */
export type HeldChallenges = {
  /** True when this run started on a session that already served earlier runs. */
  reused(): boolean;
  /** A stocked challenge for this session, or undefined when none is fresh. */
  take(): string | undefined;
  /** Fresh stocked challenges left on this session. */
  available(): number;
  /** Stock challenges issued by this session for its next reads. */
  stock(challenges: readonly string[]): void;
};

type ChannelWork<T> = (exchange: (request: unknown, options?: { last?: boolean; retry?: boolean }) => Promise<unknown>,
  session: () => VerifiedChannelSession, authenticated: () => void, challenges: HeldChallenges) => Promise<T>;

/** Keeps one verified session per participant workspace. Concurrent views wait
 * their turn instead of opening competing sessions against the same address's
 * admission budget. Any failure discards the session: the enclave closes it too. */
export class ChannelSessions {
  #idle: Held | null = null;
  #generation = 0;
  #tail: Promise<void> = Promise.resolve();
  #pending = 0;
  /** `transient`: this object serves one flow and is then dropped, so a request
   * sent with `{ last: true }` closes the session instead of leaving it parked
   * in the enclave and relay until it idles out. */
  constructor(readonly relay: ChannelRelay, readonly releaseManifest: string,
    private readonly clock: () => number = () => globalThis.performance.now(), readonly transient = false) {}
  #usable(held: Held, time: number): boolean {
    const idle = held.authenticated ? REUSE.authenticatedIdle : REUSE.anonymousIdle;
    return time - held.lastUsed < idle && time - held.openedAt < REUSE.maxLifetime && held.uses < REUSE.maxRequests;
  }
  async #acquire(fresh: boolean): Promise<{ held: Held; reused: boolean }> {
    const cached = this.#idle;
    this.#idle = null;
    if (!fresh && cached && this.#usable(cached, this.clock())) {
      // A reused session was verified earlier; the release must still not be
      // withdrawn now (the check is cached briefly, so this is usually free).
      await assertReleaseNotWithdrawn((await readReleaseManifest(this.releaseManifest)).digest, trustedNow(), this.relay.withdrawals);
      return { held: cached, reused: true };
    }
    if (cached) {
      // A fresh write or client-side expiry displaces a still-live relay lease.
      // Finish its best-effort close before asking admission for another slot.
      const generation = this.#generation;
      await this.#retire(cached);
      if (generation !== this.#generation) throw new ChannelClearedError();
    }
    const session = await verifiedSession(this.relay, this.releaseManifest);
    const time = this.clock();
    return { held: { session, openedAt: time, lastUsed: time, uses: 0, authenticated: false, challenges: [], challengesAt: time },
      reused: false };
  }
  /** Runs `work` on one session. `exchange` sends one request on it; the first
   * request on a reused session is retried once on a fresh session when it
   * fails, so callers must make the first request idempotent (a challenge),
   * or pass `retry: false` for a request bound to this session (a signed proof).
   * `fresh` skips the cached session. Canceled queued work never acquires a session. */
  async run<T>(work: ChannelWork<T>, options: { fresh?: boolean; signal?: AbortSignal } = {}): Promise<T> {
    options.signal?.throwIfAborted();
    // Bound retained callbacks as well as in-flight work. Network operations
    // retain their existing deadlines; queueing never grants another lease.
    if (this.#pending >= 16) throw new ConfidentialUnavailableError('busy');
    const generation = this.#generation, previous = this.#tail;
    let release!: () => void;
    this.#tail = new Promise<void>(resolve => { release = resolve; });
    this.#pending++;
    await previous;
    try {
      options.signal?.throwIfAborted();
      if (generation !== this.#generation) throw new ChannelClearedError();
      return await this.#run(work, options);
    } finally { this.#pending--; release(); }
  }
  async #run<T>(work: ChannelWork<T>,
    options: { fresh?: boolean; signal?: AbortSignal } = {}): Promise<T> {
    const generation = this.#generation;
    const signal = options.signal;
    const assertCurrent = () => {
      signal?.throwIfAborted();
      if (generation !== this.#generation) throw new ChannelClearedError();
    };
    let { held, reused } = await this.#acquire(options.fresh === true);
    const startedReused = reused;
    let first = true, ok = false, closed = false;
    const send = async (request: unknown, options: { last?: boolean; retry?: boolean } = {}): Promise<unknown> => {
      assertCurrent();
      const last = this.transient && options.last === true;
      try {
        const reply = await exchange(this.relay, held.session, request, last, signal);
        assertCurrent();
        held.uses++; held.lastUsed = this.clock(); first = false; closed ||= last;
        return reply;
      } catch (error) {
        assertCurrent();
        if (!(first && reused) || options.retry === false || error instanceof ConfidentialRateLimitError) throw error;
        // The reused session may have expired in the enclave; nothing ran on it.
        ({ held, reused } = await this.#acquire(true));
        assertCurrent();
        first = false;
        const reply = await exchange(this.relay, held.session, request, last, signal);
        assertCurrent();
        held.uses++; held.lastUsed = this.clock(); closed ||= last;
        return reply;
      }
    };
    const challenges: HeldChallenges = {
      reused: () => startedReused,
      take: () => {
        if (this.clock() - held.challengesAt >= CHALLENGE_STOCK_MS) held.challenges = [];
        return held.challenges.shift();
      },
      available: () => {
        if (this.clock() - held.challengesAt >= CHALLENGE_STOCK_MS) held.challenges = [];
        return held.challenges.length;
      },
      stock: list => {
        if (!held.challenges.length) held.challengesAt = this.clock();
        held.challenges.push(...list.slice(0, MAX_CHALLENGE_BATCH - held.challenges.length));
      },
    };
    try {
      assertCurrent();
      const result = await work(send, () => held.session, () => { held.authenticated = true; }, challenges);
      assertCurrent();
      ok = true;
      return result;
    } finally {
      if (generation !== this.#generation) {
        // A lock may abandon a just-issued challenge while its proof is being
        // signed. Retire only after this run settles, never alongside its call.
        if (!closed) void this.#retire(held);
      } else if (ok && !closed && held.uses > 0 && this.#usable(held, this.clock()) && !this.#idle) this.#idle = held;
    }
  }
  /** Verify (or reuse) the attested session before a view's reads. A fresh
   * session's first call fetches a challenge batch, so opening never leaves an
   * enclave slot and relay lease parked idle and the next read needs no extra
   * challenge round trip. */
  async prepare(challengeOperation: ChallengeOperation, batch = CHALLENGE_BATCH): Promise<void> {
    await this.run(async (send, _session, _authenticated, challenges) => {
      if (challenges.available() > 0) return;
      challenges.stock(await fetchChallenges(send, challengeOperation, batch));
    });
  }
  async #retire(held: Held): Promise<void> {
    // No private authority or mutation: one encrypted challenge with the final
    // frame hint releases even an abandoned protected follow-up. Do not open a
    // replacement, retry, or delay the local lock if the relay is unavailable.
    try { await exchange(this.relay, held.session, { operation: 'case.challenge' }, true); } catch { /* Existing deadlines bound an unconfirmed close. */ }
  }
  /** Drop local authority immediately and best-effort retire its idle channel. */
  clear(): void {
    const idle = this.#idle;
    this.#generation++; this.#idle = null;
    if (idle) void this.#retire(idle);
  }
}
class ChannelClearedError extends Error {}

const CHALLENGE = /^[a-f0-9]{64}$/;
/** Fetches a batch of single-use challenges issued inside the current session. */
async function fetchChallenges(send: (request: unknown) => Promise<unknown>, operation: ChallengeOperation,
  batch: number): Promise<[string, ...string[]]> {
  const count = Math.max(1, Math.min(MAX_CHALLENGE_BATCH, Math.floor(batch) || 1));
  const issued = await send({ operation, count }) as { challenges?: unknown };
  if (!Array.isArray(issued?.challenges) || !issued.challenges.length || issued.challenges.length > count ||
      issued.challenges.some(value => typeof value !== 'string' || !CHALLENGE.test(value))) throw new Error();
  return issued.challenges as [string, ...string[]];
}

const shared = new WeakMap<object, ChannelSessions>();
const retired = new WeakSet<object>();
/** Session reuse keyed on a participant workspace object (owner or firm session). */
export function channelSessionsFor(holder: object, relay: ChannelRelay, releaseManifest: string): ChannelSessions {
  if (retired.has(holder)) throw new ChannelClearedError();
  let sessions = shared.get(holder);
  if (!sessions || sessions.relay !== relay || sessions.releaseManifest !== releaseManifest) {
    sessions = new ChannelSessions(relay, releaseManifest);
    shared.set(holder, sessions);
  }
  return sessions;
}
/** Use an already verified session cache for a workspace created after it (for
 * example the owner view restored over that session). */
export function adoptChannelSessions(holder: object, sessions: ChannelSessions): void {
  if (retired.has(holder)) { sessions.clear(); throw new ChannelClearedError(); }
  if (!sessions.transient) shared.set(holder, sessions);
}
/** Drop a workspace's cached session and its unused challenges (for example
 * when the workspace is replaced or the view closes). */
export function forgetChannelSessions(holder: object): void {
  retired.add(holder);
  shared.get(holder)?.clear();
  shared.delete(holder);
}

/** A caller-supplied start time advanced by elapsed monotonic time, so each
 * signature carries the time it was made rather than when the flow began. */
export function callerClock(start?: number): () => number {
  if (start === undefined) return () => Date.now();
  const began = globalThis.performance.now();
  return () => start + Math.max(0, Math.floor(globalThis.performance.now() - began));
}

/** `callerClock` shifted by the attested enclave-time offset, read at signing
 * time so the latest verified session's offset applies. */
export function trustedClock(start?: number): () => number {
  const clock = callerClock(start);
  return () => trustedTime(clock());
}

/** Signs one participant operation on a session: a single-use challenge issued
 * in that session, then a proof bound to the same session's nonce and key. The
 * proof's issue time is taken when it is signed, not when the caller started.
 *
 * A change always fetches its own challenge first, so on a reused session the
 * first request is that challenge: a session the enclave already dropped costs
 * one retried challenge, and the change itself is never re-sent. A read
 * (`idempotent`) may instead spend a challenge stocked earlier in the same
 * session (fetched in batches of `batch`), saving a round trip; if that read
 * fails on a reused session, it runs again once on a fresh session with a new
 * challenge and proof. Only reads are ever repeated automatically. */
export async function authenticatedOperation(sessions: ChannelSessions, input: {
  sign: (challenge: string, session: VerifiedChannelSession, issuedAt: number) => Promise<string>;
  request: (proof: string) => Record<string, unknown>; challengeOperation: ChallengeOperation;
  clock?: () => number; idempotent?: boolean; batch?: number; signal?: AbortSignal;
}): Promise<unknown> {
  const batching = input.idempotent === true && !sessions.transient;
  const attempt = (fresh: boolean) => sessions.run(async (send, session, authenticated, challenges) => {
    let challenge = batching ? challenges.take() : undefined;
    const stocked = challenge !== undefined;
    if (challenge === undefined) {
      if (batching) {
        const [first, ...rest] = await fetchChallenges(send, input.challengeOperation, input.batch ?? CHALLENGE_BATCH);
        challenge = first; challenges.stock(rest);
      } else {
        const issued = await send({ operation: input.challengeOperation }) as { challenge?: unknown };
        if (typeof issued?.challenge !== 'string' || !CHALLENGE.test(issued.challenge)) throw new Error();
        challenge = issued.challenge;
      }
    }
    // The challenge may have moved to a fresh session; bind the proof to the
    // session that will carry it.
    const proof = await input.sign(challenge, session(), (input.clock ?? Date.now)());
    let reply: unknown;
    try { reply = await send(input.request(proof), { last: true, retry: false }); }
    catch (error) {
      input.signal?.throwIfAborted();
      if (stocked && challenges.reused() && !fresh && !(error instanceof ConfidentialRateLimitError) &&
          !(error instanceof ChannelClearedError)) throw new RetryRead();
      throw error;
    }
    authenticated();
    return reply;
  }, { fresh, signal: input.signal });
  try { return await attempt(false); }
  catch (error) {
    // Only a read, sent first on a reused session the enclave may have dropped.
    if (error instanceof RetryRead) return attempt(true);
    throw error;
  }
}
class RetryRead extends Error {}

/** Owner operations that only read (or, for unlock, re-supply the same key), so
 * repeating one after an ambiguous relay failure changes nothing. */
const IDEMPOTENT_OPERATIONS: ReadonlySet<ParticipantOperation> = new Set<ParticipantOperation>([
  'read-inbox', 'read-messages', 'read-state-keys', 'read-owner-envelopes', 'read-legal-roster', 'read-state',
  'open-case', 'unlock-case',
  // Setting the same address (or none) twice has the same result.
]);
export function isIdempotentOperation(operation: ParticipantOperation): boolean { return IDEMPOTENT_OPERATIONS.has(operation); }

/** Run one owner-authenticated operation: a challenge and a proof bound to the
 * same verified session, which is reused for the workspace's next operation. */
export async function ownerOperation(input: {
  relay: ChannelRelay; releaseManifest: string; now?: number; caseId: string; owner: PrivateKey;
  operation: ParticipantOperation; body: Uint8Array; sessions?: ChannelSessions;
}): Promise<unknown> {
  try {
    if (input.body.length > CHANNEL_BODY_LIMIT) throw new Error();
    const sessions = input.sessions ?? new ChannelSessions(input.relay, input.releaseManifest, undefined, true);
    return await authenticatedOperation(sessions, { challengeOperation: 'case.challenge', clock: trustedClock(input.now),
      idempotent: isIdempotentOperation(input.operation),
      sign: (challenge, session, issuedAt) => signParticipantRequest({ audience: CONFIDENTIAL_AUDIENCE, role: 'owner',
        caseId: input.caseId, organizationId: null, operation: input.operation, body: input.body, challenge,
        issuedAt, nonce: session.nonce, serverKeyId: session.serverKeyId }, input.owner),
      request: proof => ({ operation: `case.${input.operation}`, proof, body: base64(input.body) }) });
  } catch (error) { throw unavailable(error); }
}

/** Unauthenticated public operations (recovery package, release approvals). Still
 * verified-release and encrypted end to end, so the host cannot read or alter them. */
export async function publicCaseOperation(input: {
  relay: ChannelRelay; releaseManifest: string; now?: number;
  request: { operation: 'case.recovery-package' | 'case.release-approvals'; caseId: string };
  sessions?: ChannelSessions;
}): Promise<unknown> {
  try {
    const sessions = input.sessions ?? new ChannelSessions(input.relay, input.releaseManifest, undefined, true);
    return await sessions.run(send => send(input.request, { last: true }));
  } catch (error) { throw unavailable(error); }
}

export type UploadProgress = { bytesDone: number; bytesTotal: number };
/** Which chunks the relay confirmed and when. Keep it (in memory) across retries
 * of the same prepared upload so a resume sends only what is missing. */
export type ChunkUploadState = { staged: Map<string, number> };
export function createChunkUploadState(): ChunkUploadState { return { staged: new Map() }; }
/** Staged chunks expire after 24 hours; anything older than this is sent again. */
const RESTAGE_AFTER_MS = 12 * 60 * 60 * 1000;
const UPLOAD_WORKERS = 3, UPLOAD_ATTEMPTS = 4, UPLOAD_RATE_WAITS = 6;

/** Resumable upload of chunked evidence. Each chunk is re-encrypted on this
 * device from the original file (never kept in memory), checked against the
 * signed index, and staged by digest; the relay must echo exactly that digest.
 * Transient failures are retried; persistent ones throw
 * ConfidentialUploadInterruptedError with `state` recording what was confirmed. */
export async function uploadChunkedObjects(relay: ChannelRelay, objects: readonly SealedChunkedObject[],
  state: ChunkUploadState, options: {
    onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal;
    clock?: () => number; wait?: (ms: number) => Promise<void>;
  } = {}): Promise<void> {
  const clock = options.clock ?? Date.now;
  const wait = options.wait ?? (ms => new Promise(resolve => setTimeout(resolve, ms)));
  const jobs = objects.flatMap(item => {
    const index = parseChunkedIndex(item.index);
    return item.chunkDigests.map((digest, position) => ({ item, position, digest, bytes: chunkCiphertextLength(index, position) }));
  });
  const fresh = (digest: string) => {
    const at = state.staged.get(digest);
    return at !== undefined && clock() - at < RESTAGE_AFTER_MS;
  };
  const bytesTotal = jobs.reduce((sum, job) => sum + job.bytes, 0);
  let bytesDone = jobs.filter(job => fresh(job.digest)).reduce((sum, job) => sum + job.bytes, 0);
  const report = () => { try { options.onProgress?.({ bytesDone, bytesTotal }); } catch { /* display only */ } };
  report();
  const queue = jobs.filter(job => !fresh(job.digest));
  let failure: unknown = null;
  async function send(job: typeof queue[number]): Promise<void> {
    let bytes: Uint8Array | null = null;
    try {
      for (let attempt = 0, rateWaits = 0; ; ) {
        if (options.signal?.aborted || failure) throw new ConfidentialUploadInterruptedError();
        bytes ??= await job.item.chunk(job.position);
        try {
          const digest = await relay.stageChunk(bytes);
          // The host must echo the digest of exactly what we sent.
          if (digest !== job.digest) throw new ConfidentialUnavailableError();
          return;
        } catch (error) {
          if (error instanceof ConfidentialUnavailableError) throw error;
          if (error instanceof ConfidentialRateLimitError && rateWaits++ < UPLOAD_RATE_WAITS) { await wait(error.delayMs); continue; }
          if (++attempt >= UPLOAD_ATTEMPTS) throw new ConfidentialUploadInterruptedError();
          await wait(1000 * 2 ** (attempt - 1));
        }
      }
    } finally { bytes?.fill(0); }
  }
  async function worker(): Promise<void> {
    while (!failure && queue.length) {
      const job = queue.shift()!;
      try {
        await send(job);
        state.staged.set(job.digest, clock());
        bytesDone += job.bytes;
        report();
      } catch (error) { failure ??= error; }
    }
  }
  await Promise.all(Array.from({ length: Math.min(UPLOAD_WORKERS, queue.length) }, worker));
  if (failure) {
    if (failure instanceof EvidenceChangedError || failure instanceof ConfidentialUnavailableError ||
        failure instanceof ConfidentialUploadInterruptedError) throw failure;
    throw new ConfidentialUploadInterruptedError();
  }
}

/** One publish call may spend this long uploading before its proof is signed: a
 * maximum 256 MB upload over a slow connection. A resumed publish passes a fresh
 * `now`, so the proof time is always the caller's clock plus monotonic elapsed time. */
const PUBLISH_ELAPSED_LIMIT_MS = 6 * 60 * 60_000;

/** Publishes a locally prepared case. Success requires the exact caseId receipt.
 * Evidence chunks are uploaded first; pass the same `upload.state` to resume. */
export async function publishPreparedCase(input: {
  relay: ChannelRelay; releaseManifest: string; now: number;
  prepared: { caseId: string; publishBody: Uint8Array; stagedObjects: { digest: string; ciphertext: string }[];
    chunkedObjects?: readonly SealedChunkedObject[]; owner: { privateKey: PrivateKey } };
  upload?: { state?: ChunkUploadState; onProgress?: (progress: UploadProgress) => void; signal?: AbortSignal;
    wait?: (ms: number) => Promise<void> };
  /** Called just before the publish request itself may leave this device. From
   * then on a failure is ambiguous: the report may already exist, so callers keep
   * the same prepared submission and retry it (the service accepts that exact
   * retry idempotently) rather than preparing a new report. */
  onPublishSending?: () => void;
}): Promise<{ caseId: string }> {
  const started = globalThis.performance.now();
  const currentTime = () => {
    const elapsed = globalThis.performance.now() - started;
    const time = input.now + Math.floor(Math.max(0, elapsed));
    if (!Number.isFinite(elapsed) || elapsed > PUBLISH_ELAPSED_LIMIT_MS || !Number.isSafeInteger(time) || time <= 0) throw new ConfidentialUnavailableError();
    return time;
  };
  // Verify the release before uploading anything, so an unverifiable backend
  // receives neither ciphertext nor the owner's proof. The verified session is
  // kept for the publish itself when the upload is quick enough; otherwise the
  // enclave has reclaimed it and the publish opens a fresh one.
  const sessions = new ChannelSessions(input.relay, input.releaseManifest, undefined, true);
  try {
    const reply = await sessions.run(send => send({ operation: 'case.challenge' })) as { challenge?: unknown };
    if (typeof reply?.challenge !== 'string' || !/^[a-f0-9]{64}$/.test(reply.challenge)) throw new Error();
  } catch (error) { throw unavailable(error); }
  for (const item of input.prepared.stagedObjects) {
    let digest: string;
    try { digest = await input.relay.stage(item.ciphertext); } catch (error) { throw unavailable(error); }
    // The host must echo the digest of exactly what we sent.
    if (digest !== item.digest) throw new ConfidentialUnavailableError();
  }
  if (input.prepared.chunkedObjects?.length) {
    await uploadChunkedObjects(input.relay, input.prepared.chunkedObjects, input.upload?.state ?? createChunkUploadState(),
      { onProgress: input.upload?.onProgress, signal: input.upload?.signal, wait: input.upload?.wait });
  }
  input.onPublishSending?.();
  const reply = await ownerOperation({ relay: input.relay, releaseManifest: input.releaseManifest, now: currentTime(),
    caseId: input.prepared.caseId, owner: input.prepared.owner.privateKey, operation: 'publish-case',
    body: input.prepared.publishBody, sessions }) as { caseId?: unknown };
  if (reply?.caseId !== input.prepared.caseId) throw new ConfidentialUnavailableError();
  return { caseId: input.prepared.caseId };
}

export function confidentialBodyFits(body: Uint8Array): boolean { return body.length <= CHANNEL_BODY_LIMIT; }
