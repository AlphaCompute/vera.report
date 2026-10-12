import { decodeAttestationCbor } from '../confidential/attestationCbor.js';
import type { AuthenticatedTimeBound } from './roughtime.js';

/** Enclave time that does not rely on the host clock alone (architecture hole 8).
 *
 * Anchor: the `timestamp` (UTC ms) of an attestation document this enclave just
 * obtained from its LOCAL NSM device. The Nitro hypervisor produces it; the
 * parent-instance host cannot forge it (same stance as `verifySelfRelease`).
 * Between anchors, time advances with an in-process monotonic clock, so
 * `now()` = anchor timestamp + monotonic elapsed, and never decreases.
 *
 * The host clock (`Date.now()`, which a host can steer) is only a consistency
 * check: if it has regressed below trusted time by more than `toleranceMs`
 * (rollback that could resurrect an expired grant) or run ahead by more than
 * `toleranceMs` (misconfiguration or manipulation), `now()` throws and every
 * operation using it fails closed. A stale anchor (refresh failing for longer
 * than `maxAnchorAgeMs`) also fails closed. A re-anchor whose NSM timestamp
 * regresses against the running trusted time is refused.
 *
 * Optional external bound (`external`, Roughtime servers pinned in the measured
 * configuration, see roughtime.ts): on every (re-)anchor the NSM-anchored time
 * is compared with authenticated server intervals. At least `quorum` of them
 * must contain it (± `toleranceMs`); if `quorum` verified intervals exclude it,
 * `now()` fails closed until a later refresh agrees again, and if too few
 * servers answer, the last agreement stays usable for at most `maxAgeMs`. The
 * clock starts only after a first agreement. Without `external` the behavior is
 * unchanged.
 *
 * Limits: without `external`, this bounds but does not eliminate drift of the
 * NSM/hypervisor clock itself. With it, trust in time additionally rests on the
 * pinned Roughtime servers (a quorum of them must be honest and reachable).
 */
export type TrustedClock = {
  /** Trusted UTC milliseconds. Throws when time cannot be established. */
  now(): number;
  /** Re-anchor on a fresh local NSM document. */
  refresh(): Promise<void>;
  /** Stop the periodic refresh timer. */
  stop(): void;
};
export type TrustedClockOptions = {
  /** Returns a fresh attestation document from the local NSM device (COSE_Sign1 bytes). */
  attest: () => Promise<Uint8Array>;
  /** In-process monotonic milliseconds (default `performance.now()`). */
  monotonic?: () => number;
  /** Host wall clock, checked for consistency only (default `Date.now`). */
  hostClock?: () => number;
  toleranceMs?: number;
  maxAnchorAgeMs?: number;
  /** Periodic re-anchor interval; 0 disables the timer (tests). */
  refreshMs?: number;
  /** Optional authenticated external time (Roughtime through the host relay). */
  external?: ExternalTimeBound;
};
export type ExternalTimeBound = {
  /** One entry per configured server: a verified interval, or null (no valid answer). */
  sample(monotonic: () => number): Promise<(AuthenticatedTimeBound | null)[]>;
  quorum: number;
  /** Allowed disagreement beyond each interval. */
  toleranceMs: number;
  /** How long one agreement stays usable while servers are unreachable (default `maxAnchorAgeMs`). */
  maxAgeMs?: number;
};

const FAILURE = 'Trusted time unavailable';
const MIN_TIMESTAMP = Date.UTC(2024, 0, 1), MAX_TIMESTAMP = Date.UTC(2200, 0, 1);
function fail(): never { throw new Error(FAILURE); }

/** The NSM `timestamp` field of a local attestation document. Parsing grants no
 * trust by itself: callers must obtain the document from the local NSM device. */
export function nsmDocumentTimestamp(document: Uint8Array): number {
  try {
    const cose = decodeAttestationCbor(document, true);
    if (!Array.isArray(cose) || cose.length !== 4 || !(cose[2] instanceof Uint8Array)) fail();
    const payload = decodeAttestationCbor((cose as unknown[])[2] as Uint8Array);
    const timestamp = payload instanceof Map ? payload.get('timestamp') : null;
    if (typeof timestamp !== 'number' || !Number.isSafeInteger(timestamp) ||
        timestamp < MIN_TIMESTAMP || timestamp > MAX_TIMESTAMP) fail();
    return timestamp as number;
  } catch { return fail(); }
}

export async function createTrustedClock(options: TrustedClockOptions): Promise<TrustedClock> {
  const monotonic = options.monotonic ?? (() => performance.now());
  const hostClock = options.hostClock ?? Date.now;
  const tolerance = options.toleranceMs ?? 60_000;
  const maxAge = options.maxAnchorAgeMs ?? 30 * 60_000;
  const refreshMs = options.refreshMs ?? 5 * 60_000;
  if (!(tolerance > 0) || !(maxAge > 0) || !(refreshMs >= 0)) fail();
  const external = options.external;
  const externalMaxAge = external?.maxAgeMs ?? maxAge;
  if (external && (!Number.isSafeInteger(external.quorum) || external.quorum < 1 || !(external.toleranceMs > 0) ||
      !(externalMaxAge > 0))) fail();
  let anchor: { timestamp: number; at: number } | null = null, floor = 0, lastMonotonic = -Infinity;
  /** Monotonic time of the last external agreement (null: none, or refuted). */
  let agreedAt: number | null = null;
  function tick(): number {
    const at = monotonic();
    if (!Number.isFinite(at) || at < lastMonotonic) fail();
    lastMonotonic = at;
    return at;
  }

  function projected(at: number, bounded = true): number {
    if (!anchor) fail();
    const elapsed = at - anchor!.at;
    if (!Number.isFinite(elapsed) || elapsed < 0 || (bounded && elapsed > maxAge)) fail();
    return anchor!.timestamp + Math.floor(elapsed);
  }
  async function refresh(): Promise<void> {
    const timestamp = nsmDocumentTimestamp(await options.attest());
    const at = tick();
    // The NSM clock must not regress against time we have already vouched for.
    if (anchor && timestamp < Math.max(floor, projected(at, false)) - tolerance) fail();
    anchor = { timestamp, at };
    if (external) await checkExternal();
  }
  async function checkExternal(): Promise<void> {
    const samples = await external!.sample(() => tick());
    let agree = 0, disagree = 0;
    for (const sample of samples) {
      if (!sample) continue;
      const trusted = Math.max(floor, projected(sample.receivedAt, false));
      if (trusted >= sample.earliest - external!.toleranceMs && trusted <= sample.latest + external!.toleranceMs) agree++;
      else disagree++;
    }
    if (agree >= external!.quorum) agreedAt = tick();
    else if (disagree >= external!.quorum) agreedAt = null;
  }
  await refresh();
  if (external && agreedAt === null) fail();
  const timer = refreshMs > 0 ? setInterval(() => { refresh().catch(() => undefined); }, refreshMs) : null;
  timer?.unref?.();
  return {
    now() {
      const at = tick();
      if (external && (agreedAt === null || at - agreedAt > externalMaxAge)) fail();
      const trusted = Math.max(floor, projected(at));
      const host = hostClock();
      if (!Number.isFinite(host) || host < trusted - tolerance || host > trusted + tolerance) fail();
      floor = trusted;
      return trusted;
    },
    refresh,
    stop() { if (timer) clearInterval(timer); },
  };
}
