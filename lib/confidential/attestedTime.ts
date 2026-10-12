/** Attested enclave time on a participant device (architecture hole 8).
 *
 * Every verified channel session carries an AWS-signed NSM timestamp. The
 * browser keeps the latest one as an anchor (in memory only) together with the
 * device clock and the in-page monotonic clock at the moment it was verified.
 * Two readings follow from it:
 *
 *  - `trustedTime(deviceNow)`: the time this device SIGNS with (issue times of
 *    proofs, checkpoints, grants, messages, requests). It shifts a device-clock
 *    reading by the offset measured at verification and is based on the NSM
 *    timestamp itself (the earliest the enclave's time can be), so a fast
 *    device never produces statements "from the future".
 *
 *  - `trustedNow()`: the time this device DECIDES with (is a grant, request,
 *    membership lease or withdrawal list still valid?). It adds the round trip
 *    of the verified exchange (the latest the enclave's time can be, because the
 *    document was produced after the fresh nonce was chosen), and advances with
 *    whichever of the device and monotonic clocks moved further since the anchor.
 *    So neither a device clock set back nor a relay that delays its answer can
 *    make something that has expired look valid. The price is that a valid item
 *    can look expired up to one verification round trip early (or by a forward
 *    jump of this device's own clock, which fails closed).
 *
 * Without an anchor (no verified session yet on this page) both readings fall
 * back to the device clock. Callers that must not decide on an unverified
 * clock re-check once a session has verified (see `verifiedSession`), and
 * attestation verification itself refuses a device clock more than a few
 * minutes from the NSM time, so no session (and therefore no case data) is
 * ever obtained on a badly wrong clock.
 */
import { setPgpClock } from '../../enclave/src/confidential/pgpClock';

type Anchor = { timestamp: number; roundTrip: number; device: number; monotonic: number };
let anchor: Anchor | null = null;
let clocks = { device: () => Date.now(), monotonic: () => globalThis.performance.now() };

// OpenPGP packet dates must follow the same clock as signed protocol fields.
// Otherwise a fast device passes attestation but its first signature is rejected
// as being from the future; a slow device rejects the enclave's fresh reply key.
setPgpClock({ signing: () => trustedTime(clocks.device()), verification: () => trustedNow() });

/** Largest round trip credited to an anchor: longer exchanges are still usable
 * but decisions use this bound (the attestation window refuses older evidence). */
const MAX_ROUND_TRIP_MS = 6 * 60_000;

/** Records the NSM timestamp of a session that just verified. `startedAt` is the
 * monotonic time before the fresh nonce was sent (defaults to now: no credit). */
export function recordAttestedTime(timestamp: number, startedAt?: number): void {
  if (!Number.isSafeInteger(timestamp) || timestamp <= 0) return;
  const monotonic = clocks.monotonic(), device = clocks.device();
  if (!Number.isFinite(monotonic) || !Number.isFinite(device)) return;
  const roundTrip = startedAt === undefined || !Number.isFinite(startedAt) ? 0
    : Math.min(MAX_ROUND_TRIP_MS, Math.max(0, Math.ceil(monotonic - startedAt)));
  anchor = { timestamp, roundTrip, device, monotonic };
}

/** Monotonic reading for `recordAttestedTime(…, startedAt)`. */
export function attestedTimeMark(): number { return clocks.monotonic(); }

export function resetTrustedTime(): void { anchor = null; }
export function hasAttestedTime(): boolean { return anchor !== null; }

function elapsed(current: Anchor): { monotonic: number; device: number } {
  return { monotonic: Math.max(0, Math.floor(clocks.monotonic() - current.monotonic)),
    device: Math.floor(clocks.device() - current.device) };
}

/** Enclave time for a device-clock reading, for signing (see above): the
 * reading shifted by the offset between the NSM timestamp and this device's
 * clock when the latest session verified. Callers' readings (`callerClock`)
 * are the device clock at flow start plus monotonic elapsed time, so the offset
 * is applied as fixed at the anchor. Signing times never decide validity here:
 * the enclave checks them against its own clock and refuses one from the future. */
export function trustedTime(now: number): number {
  const current = anchor;
  return current ? now + (current.timestamp - current.device) : now;
}

/** Attested enclave time for every expiry and validity decision on this
 * device (see above). Without an argument: now. With a device-clock reading
 * (for example the `now` a flow started with): that reading mapped onto the
 * same decision clock, so `trustedNow(Date.now()) === trustedNow()`. Pure policy
 * functions take this value as their `now`. */
export function trustedNow(deviceNow?: number): number {
  const current = anchor, device = clocks.device();
  const reading = deviceNow === undefined ? device : deviceNow;
  if (!current) return reading;
  const since = elapsed(current);
  return reading + (current.timestamp + current.roundTrip + Math.max(since.monotonic, since.device, 0) - device);
}

/** Tests only: substitute the device and monotonic clocks; undefined restores them. */
export function setAttestedTimeClocksForTests(replacement?: { device: () => number; monotonic: () => number }): void {
  clocks = replacement ?? { device: () => Date.now(), monotonic: () => globalThis.performance.now() };
  anchor = null;
}
