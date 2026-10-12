// Test-only time travel for the local stack: one forward-only offset shared by
// the synthetic NSM timestamps (./syntheticNitro.ts), the enclave's trusted
// clock (composeConfidentialServer `timeShift`), this process's wall clock and,
// through support/time.ts, the participants' browser clocks and identity
// tokens. Attested time then moves as if that much time had passed, for example
// past a grant's end. Production never composes this: `startConfidentialServer`
// passes no shift.
//
// The wall clock of this process (global setup: API, storage RPC and enclave
// composition) moves too, because OpenPGP checks the signature times of what
// the (shifted) browsers sign against `new Date()`. Only `Date.now()` and
// `new Date()` / `Date()` without arguments move; `performance.now()`, timers
// and the Next server (its own process) keep real time.
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer } from 'node:http';
import type { AddressInfo } from 'node:net';
import type { TimeShift } from '../../../enclave/src/confidential-server';

const RealDate = Date;
const realNow = RealDate.now.bind(RealDate);

export type StackTimeShift = TimeShift & {
  /** Wall clock plus the offset: the time every stack component agrees on. */
  now(): number;
  /** Moves the offset forward (never back: trusted time refuses to regress) and
   * waits until the enclave has re-anchored on it. */
  set(offsetMs: number): Promise<void>;
  /** Puts this process's real `Date` back (stack teardown). */
  restore(): void;
};

export function createStackTimeShift(): StackTimeShift {
  let offset = 0;
  const listeners: (() => Promise<void>)[] = [];
  const now = () => realNow() + offset;
  const shifted = new Proxy(RealDate, {
    construct: (target, args, newTarget) => Reflect.construct(target, args.length ? args : [now()], newTarget),
    apply: (target, self, args) => args.length ? Reflect.apply(target, self, args) : new target(now()).toString(),
    get: (target, property, receiver) => property === 'now' ? now : Reflect.get(target, property, receiver),
  });
  return {
    offsetMs: () => offset,
    now,
    onShift(listener) { listeners.push(listener); },
    async set(offsetMs) {
      if (!Number.isSafeInteger(offsetMs) || offsetMs < offset) throw new Error('The stack clock only moves forward');
      offset = offsetMs;
      if (offset) globalThis.Date = shifted;
      for (const listener of listeners) await listener();
    },
    restore() { globalThis.Date = RealDate; },
  };
}

/** Loopback-only control for specs, which run in Playwright workers apart from
 * the global setup that owns the stack. `GET /time` reads the offset and
 * `POST /time {offsetMs}` moves it; both need the bearer token from the state
 * file (mode 0600). */
export async function startTimeControl(shift: StackTimeShift): Promise<{ url: string; token: string; close(): Promise<void> }> {
  const token = randomBytes(32).toString('hex');
  const expected = Buffer.from(`Bearer ${token}`);
  const server = createServer((req, res) => {
    const reply = (status: number, value?: unknown) => {
      res.writeHead(status, { 'Content-Type': 'application/json' });
      res.end(value === undefined ? '{}' : JSON.stringify(value));
    };
    const presented = Buffer.from(req.headers.authorization ?? '');
    if (presented.length !== expected.length || !timingSafeEqual(presented, expected)) return reply(403);
    if (req.url !== '/time') return reply(404);
    if (req.method === 'GET') return reply(200, { offsetMs: shift.offsetMs() });
    if (req.method !== 'POST') return reply(405);
    let body = '';
    req.setEncoding('utf8');
    req.on('data', chunk => { body += chunk; if (body.length > 1024) req.destroy(); });
    req.on('end', async () => {
      try {
        await shift.set((JSON.parse(body) as { offsetMs: number }).offsetMs);
        reply(200, { offsetMs: shift.offsetMs() });
      } catch (error) { reply(409, { error: (error as Error).message }); }
    });
  });
  await new Promise<void>((done, fail) => { server.once('error', fail); server.listen(0, '127.0.0.1', done); });
  return { url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/time`, token,
    close: () => new Promise<void>(done => { server.close(() => done()); server.closeAllConnections(); }) };
}
