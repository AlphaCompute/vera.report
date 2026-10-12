import { webcrypto } from 'node:crypto';

// Session reuse and challenge batching on the browser side of the attested
// channel. The AWS quote check is mocked; channel encryption, the enclave session
// core and its per-session challenge ledger are real. The dispatch below is a
// TEST stand-in for the case service.
jest.mock('../../../enclave/src/confidential/attestation', () => ({
  verifyApplicationAttestation: async (_document: Uint8Array, publicKey: Uint8Array) =>
    ({ publicKey: new Uint8Array(publicKey), timestamp: Date.now(), verifiedAt: Date.now() }),
}));

import { generateKey } from '../../../enclave/src/confidential/pgp';
import { canonicalReleaseManifest } from '../../../enclave/src/confidential/releaseManifest';
import { createSessionCore, SESSION_LIMITS } from '../../../enclave/src/application-channel-sessions';
import type { ChannelDispatch } from '../../../enclave/src/application-channel-sessions';
import { ApplicationChannelIdentity } from '../../../enclave/src/application-channel-identity';
import { CASE_CHALLENGE_BATCH } from '../../../enclave/src/session-challenges';
import { CHALLENGE_BATCH, ChannelSessions, authenticatedOperation, adoptChannelSessions,
  channelSessionsFor, forgetChannelSessions } from '../../../lib/confidential/client';
import type { ChannelRelay } from '../../../lib/confidential/client';
import { ConfidentialRateLimitError } from '../../../lib/confidential/readRetry';

const hex = (n: number) => n.toString(16).padStart(64, '0');
const MANIFEST = canonicalReleaseManifest({ format: 'vera-confidential-release/v1',
  sourceRepository: 'https://github.com/example/vera', sourceCommit: '1'.repeat(40),
  eifSha256: hex(11), imageSha256: hex(12), configurationSha256: hex(13), provenanceSha256: hex(14),
  protocolVersion: 'vera-confidential-channel/v1', dataFormatVersion: 'vera-confidential-case/v1',
  measurements: { pcr0: '11'.repeat(48), pcr1: '22'.repeat(48), pcr2: '33'.repeat(48) } });
const decode = (body: Uint8Array) => JSON.parse(new TextDecoder().decode(body));
const encode = (value: unknown) => new TextEncoder().encode(JSON.stringify(value));
const random = () => Buffer.from(globalThis.crypto.getRandomValues(new Uint8Array(32))).toString('hex');

describe('ChannelSessions: several operations per attested session', () => {
  let keys: Awaited<ReturnType<typeof generateKey>>;
  let core: ReturnType<typeof createSessionCore>;
  let clock = 0;
  const log = { opens: 0, calls: 0, challengeFetches: 0, applied: [] as number[] };
  let failNextCall: 'transport' | 'rate' | 'after-apply' | null = null;

  /** TEST stand-in: issues challenges into the session ledger and accepts an
   * operation only with an unused challenge issued in the same session. */
  const dispatch: ChannelDispatch = async (body, context) => {
    const request = decode(body);
    if (request.operation === 'case.challenge') {
      log.challengeFetches++;
      const count = request.count ?? 1;
      const challenges = Array.from({ length: count }, random);
      challenges.forEach((challenge, index) => context.challenges.add(challenge, 10_000_000, 1, index === 0));
      return encode(request.count === undefined ? { challenge: challenges[0], expiresAt: 10_000_000 } : { challenges, expiresAt: 10_000_000 });
    }
    if (request.operation === 'case.test-op') {
      const proof = JSON.parse(request.proof);
      if (proof.nonce !== context.nonce || !context.challenges.consume(proof.challenge, 1)) throw new Error('unauthorized');
      context.authenticated?.();
      log.applied.push(request.value);
      return encode({ ok: request.value });
    }
    throw new Error('unknown');
  };
  const relay: ChannelRelay = {
    async stage() { throw new Error('not used'); },
    async open(nonce) {
      log.opens++;
      const identity = await core.open(nonce);
      return { document: new Uint8Array([1]), publicKey: new Uint8Array(Buffer.from(identity.publicKey, 'base64')) };
    },
    async call(nonce, ciphertext, last) {
      log.calls++;
      const mode = failNextCall; failNextCall = null;
      if (mode === 'transport') throw new Error('relay down');
      if (mode === 'rate') throw new ConfidentialRateLimitError('2');
      const reply = await core.execute(nonce, ciphertext, { last });
      if (mode === 'after-apply') throw new Error('reply dropped'); // Applied, but the reply never arrives.
      return reply;
    },
  };
  const operation = (sessions: ChannelSessions, value: number, idempotent: boolean) => authenticatedOperation(sessions, {
    challengeOperation: 'case.challenge', idempotent,
    sign: async (challenge, session) => JSON.stringify({ challenge, nonce: session.nonce }),
    request: proof => ({ operation: 'case.test-op', proof, value }),
  });
  const read = (sessions: ChannelSessions, value: number) => operation(sessions, value, true);
  const change = (sessions: ChannelSessions, value: number) => operation(sessions, value, false);

  beforeAll(async () => {
    if (!globalThis.crypto) Object.defineProperty(globalThis, 'crypto', { value: webcrypto });
    keys = await generateKey({ type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'Synthetic channel' }], format: 'object' });
  });
  beforeEach(() => {
    core?.close();
    core = createSessionCore(dispatch, async nonce => new ApplicationChannelIdentity(keys.privateKey,
      { nonce, publicKey: Buffer.from(keys.publicKey.write()).toString('base64'), document: 'synthetic-not-attestation' }), () => clock);
    clock = 0; log.opens = 0; log.calls = 0; log.challengeFetches = 0; log.applied = []; failNextCall = null;
  });
  afterAll(() => core?.close());
  const workspace = () => new ChannelSessions(relay, MANIFEST, () => clock);

  test('the client batch fits inside what the enclave issues', () => {
    expect(CHALLENGE_BATCH).toBeLessThanOrEqual(CASE_CHALLENGE_BATCH);
  });

  test('reads share one attested session and one challenge batch', async () => {
    const sessions = workspace();
    for (let value = 0; value < CHALLENGE_BATCH; value++) await expect(read(sessions, value)).resolves.toEqual({ ok: value });
    expect(log.opens).toBe(1);
    expect(log.challengeFetches).toBe(1);
    expect(log.calls).toBe(1 + CHALLENGE_BATCH);
    await read(sessions, 9); // The next read fetches a new batch on the same session.
    expect(log.opens).toBe(1);
    expect(log.challengeFetches).toBe(2);
  });

  test('concurrent workspace reads reuse one channel instead of opening a session per view', async () => {
    const sessions = workspace();
    const values = Array.from({ length: 8 }, (_, index) => index);
    await expect(Promise.all(values.map(value => read(sessions, value))))
      .resolves.toEqual(values.map(value => ({ ok: value })));
    expect(log.opens).toBe(1);
    expect(log.challengeFetches).toBe(2);
    expect(log.applied).toEqual(values);
  });

  test('workspace backpressure is bounded and a failed operation releases the queue', async () => {
    const sessions = workspace();
    let resume!: () => void, entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const first = sessions.run(async () => { entered(); await gate; throw new Error('synthetic failure'); });
    const failed = expect(first).rejects.toThrow('synthetic failure');
    await started;
    const queued = Array.from({ length: 15 }, (_, index) => read(sessions, index));
    await expect(read(sessions, 99)).rejects.toMatchObject({ reason: 'busy' });
    expect(log.opens).toBe(1); // Only the running operation has opened a channel.
    resume();
    await failed;
    await Promise.all(queued);
    expect(log.applied).toEqual(Array.from({ length: 15 }, (_, index) => index));
    expect(log.opens).toBe(2); // The failed channel is discarded; the rest share its replacement.
  });

  test('locking cancels queued work before it can acquire a session or send a change', async () => {
    const sessions = workspace();
    let resume!: () => void, entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const first = sessions.run(async () => { entered(); await gate; });
    await started;
    const queued = change(sessions, 2);
    const failed = [expect(first).rejects.toThrow(), expect(queued).rejects.toThrow()];
    sessions.clear();
    resume();
    await Promise.all(failed);
    expect(log.opens).toBe(1);
    expect(log.applied).toEqual([]);
    await read(sessions, 3);
    expect(log.applied).toEqual([3]);
  });

  test('a change always fetches its own challenge first on the shared session', async () => {
    const sessions = workspace();
    await read(sessions, 1); // Leaves stocked challenges for reads.
    const before = log.calls;
    await expect(change(sessions, 2)).resolves.toEqual({ ok: 2 });
    expect(log.calls - before).toBe(2); // Challenge, then the change.
    expect(log.opens).toBe(1);
  });

  test('prepare verifies the session and stocks a batch, so the first read needs one call', async () => {
    const sessions = workspace();
    await sessions.prepare('case.challenge');
    expect(log.opens).toBe(1);
    await sessions.prepare('case.challenge'); // Stock left: nothing sent.
    expect(log.calls).toBe(1);
    await read(sessions, 1);
    expect(log.calls).toBe(2);
  });

  test('locking releases an abandoned challenge follow-up instead of parking its lease until expiry', async () => {
    const sessions = workspace();
    const opened = jest.spyOn(relay, 'open');
    try {
      await sessions.prepare('case.challenge');
      const nonce = opened.mock.calls[0][0];
      expect(core.release(nonce)).toBe(false); // The pending proof is protected from relay eviction.
      sessions.clear();
      // Closing is best effort and must not delay removal of local authority.
      for (let attempt = 0; attempt < 100 && core.hasPendingSession(nonce); attempt++) {
        await new Promise(resolve => setTimeout(resolve, 10));
      }
      expect(core.hasPendingSession(nonce)).toBe(false);
      expect(log.opens).toBe(1);
      expect(log.applied).toEqual([]);
    } finally { opened.mockRestore(); }
  });

  test.each(['fresh', 'expired'] as const)('%s acquisition retires the displaced cached lease before opening another', async reason => {
    let clientClock = 0;
    const sessions = new ChannelSessions(relay, MANIFEST, () => clientClock);
    const open = relay.open;
    const opened = jest.spyOn(relay, 'open');
    try {
      await sessions.prepare('case.challenge');
      const displaced = opened.mock.calls[0][0];
      expect(core.release(displaced)).toBe(false); // A protected follow-up cannot be evicted by the relay.
      if (reason === 'expired') clientClock += SESSION_LIMITS.authenticatedIdle;
      opened.mockImplementation(async nonce => {
        expect(core.hasPendingSession(displaced)).toBe(false);
        return open(nonce);
      });
      const replacement = await sessions.run(async (send, session) => {
        await send({ operation: 'case.challenge' });
        return session().nonce;
      }, { fresh: reason === 'fresh' });
      expect(replacement).not.toBe(displaced);
      expect(core.hasPendingSession(replacement)).toBe(true);
      expect(opened).toHaveBeenCalledTimes(2);
      expect(log.applied).toEqual([]);
    } finally { opened.mockRestore(); }
  });

  test('locking during displaced-session cleanup cancels replacement admission', async () => {
    const sessions = workspace();
    await sessions.prepare('case.challenge');
    let closing!: () => void, resume!: () => void;
    const started = new Promise<void>(resolve => { closing = resolve; });
    const gate = new Promise<void>(resolve => { resume = resolve; });
    const call = relay.call;
    const pendingCall = jest.spyOn(relay, 'call').mockImplementation(async (...args) => {
      const reply = await call(...args);
      if (args[2]) { closing(); await gate; }
      return reply;
    });
    try {
      const pending = sessions.run(async send => send({ operation: 'case.challenge' }), { fresh: true });
      const rejected = expect(pending).rejects.toThrow();
      await started;
      sessions.clear();
      resume();
      await rejected;
      expect(log.opens).toBe(1);
      expect(log.applied).toEqual([]);
    } finally { resume(); pendingCall.mockRestore(); }
  });

  test('stocked challenges never cross sessions: a rotated session fetches its own', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    clock += SESSION_LIMITS.authenticatedIdle; // The client stops reusing the session before the enclave drops it.
    await expect(read(sessions, 2)).resolves.toEqual({ ok: 2 });
    expect(log.opens).toBe(2);
    expect(log.challengeFetches).toBe(2);
  });

  test('locking during signing cancels the change and retires its protected follow-up after the run settles', async () => {
    const sessions = workspace();
    let resume!: () => void, entered!: () => void, nonce = '';
    const signing = new Promise<void>(resolve => { entered = resolve; });
    const pending = authenticatedOperation(sessions, {
      challengeOperation: 'case.challenge', idempotent: false,
      sign: async (challenge, session) => {
        nonce = session.nonce; entered();
        await new Promise<void>(resolve => { resume = resolve; });
        return JSON.stringify({ challenge, nonce });
      },
      request: proof => ({ operation: 'case.test-op', proof, value: 99 }),
    });
    await signing;
    expect(core.release(nonce)).toBe(false);
    sessions.clear();
    expect(log.calls).toBe(1); // Do not close concurrently with unsettled work.
    const rejected = expect(pending).rejects.toThrow();
    resume(); await rejected;
    for (let attempt = 0; attempt < 100 && core.hasPendingSession(nonce); attempt++) {
      await new Promise(resolve => setTimeout(resolve, 10));
    }
    expect(core.hasPendingSession(nonce)).toBe(false);
    expect(log.opens).toBe(1);
    expect(log.applied).toEqual([]);
  });

  test('a read that fails on a reused session runs again once, on a fresh session with a new challenge', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    failNextCall = 'transport'; // Fails the read signed with a stocked challenge.
    await expect(read(sessions, 2)).resolves.toEqual({ ok: 2 });
    expect(log.opens).toBe(2);
    expect(log.applied).toEqual([1, 2]);
  });

  test('a change is never re-sent automatically, even when the enclave applied it', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    failNextCall = null;
    const pending = change(sessions, 2);
    // Fail the change itself (the call after its challenge) after the enclave applied it.
    const call = relay.call;
    let seen = 0;
    relay.call = async (...args) => { if (++seen === 2) failNextCall = 'after-apply'; return call(...args); };
    try { await expect(pending).rejects.toThrow(); } finally { relay.call = call; }
    expect(log.applied).toEqual([1, 2]); // Applied once, never twice.
    expect(log.opens).toBe(1);
  });

  test('a failed challenge fetch on a reused session is retried on a fresh one before any change is sent', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    failNextCall = 'transport';
    await expect(change(sessions, 2)).resolves.toEqual({ ok: 2 });
    expect(log.opens).toBe(2);
    expect(log.applied).toEqual([1, 2]);
  });

  test('a rate limit or a failure on a fresh session is not retried', async () => {
    const sessions = workspace();
    failNextCall = 'transport';
    await expect(read(sessions, 1)).rejects.toThrow();
    expect(log.opens).toBe(1);
    await read(sessions, 2);
    failNextCall = 'rate';
    await expect(read(sessions, 3)).rejects.toBeInstanceOf(ConfidentialRateLimitError);
    expect(log.opens).toBe(2);
    expect(log.applied).toEqual([2]);
  });

  test('a one-flow (transient) session does not stock challenges', async () => {
    const sessions = new ChannelSessions(relay, MANIFEST, () => clock, true);
    await read(sessions, 1);
    expect(log.challengeFetches).toBe(1);
    expect(log.calls).toBe(2);
  });

  test('locking during signing prevents the pending read and does not resurrect a cached session', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    let resume!: () => void, entered!: () => void;
    const signing = new Promise<void>(resolve => { entered = resolve; });
    const pending = authenticatedOperation(sessions, {
      challengeOperation: 'case.challenge', idempotent: true,
      sign: async (challenge, session) => {
        entered();
        await new Promise<void>(resolve => { resume = resolve; });
        return JSON.stringify({ challenge, nonce: session.nonce });
      },
      request: proof => ({ operation: 'case.test-op', proof, value: 2 }),
    });
    await signing;
    sessions.clear();
    const rejected = expect(pending).rejects.toThrow();
    resume();
    await rejected;
    expect(log.applied).toEqual([1]);
    expect(log.opens).toBe(1); // No automatic retry after a lock.
    await read(sessions, 3);
    expect(log.opens).toBe(2);
    expect(log.applied).toEqual([1, 3]);
  });

  test('cancelling a read while signing never retries the stocked challenge on another session', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    const calls = log.calls;
    const controller = new AbortController();
    await expect(authenticatedOperation(sessions, {
      challengeOperation: 'case.challenge', idempotent: true, signal: controller.signal,
      sign: async (challenge, session) => {
        controller.abort();
        return JSON.stringify({ challenge, nonce: session.nonce });
      },
      request: proof => ({ operation: 'case.test-op', proof, value: 2 }),
    })).rejects.toMatchObject({ name: 'AbortError' });
    expect(log.calls).toBe(calls);
    expect(log.opens).toBe(1);
    expect(log.applied).toEqual([1]);
    // The abandoned session cannot be reused by a later operation.
    await read(sessions, 3);
    expect(log.opens).toBe(2);
    expect(log.applied).toEqual([1, 3]);
  });

  test('a retired workspace cannot open or adopt another session from a late helper continuation', () => {
    const holder = {};
    channelSessionsFor(holder, relay, MANIFEST);
    forgetChannelSessions(holder);
    expect(() => channelSessionsFor(holder, relay, MANIFEST)).toThrow();
    expect(() => adoptChannelSessions(holder, workspace())).toThrow();
    expect(() => channelSessionsFor({}, relay, MANIFEST)).not.toThrow();
    expect(log.opens).toBe(0);
  });

  test('locking with a reply in flight discards its result and session', async () => {
    const sessions = workspace();
    await read(sessions, 1);
    const call = relay.call;
    let resume!: () => void, entered!: () => void;
    const received = new Promise<void>(resolve => { entered = resolve; });
    relay.call = async (...args) => {
      const reply = await call(...args);
      entered();
      await new Promise<void>(resolve => { resume = resolve; });
      return reply;
    };
    try {
      const pending = read(sessions, 2);
      await received;
      sessions.clear();
      const rejected = expect(pending).rejects.toThrow();
      resume();
      await rejected;
      expect(log.opens).toBe(1);
      expect(log.applied).toEqual([1, 2]);
    } finally { relay.call = call; }
    await read(sessions, 3);
    expect(log.opens).toBe(2);
  });
});
