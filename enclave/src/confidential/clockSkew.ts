/** Participant devices, the admin's device and the enclave each read their own
 * clock. A signed issue time from another clock may be ahead of the checker's
 * time by this much and still count as "not in the future". This is not a
 * freshness bound: replay protection comes from single-use challenges, session
 * nonces, hash-chained checkpoints and revisions, never from issue times. */
export const CLOCK_SKEW_MS = 5 * 60_000;

/** True when `issuedAt` (another party's clock) is not later than `now` (this
 * checker's clock) beyond the tolerated skew. */
export function issuedNotAfter(issuedAt: number, now: number): boolean {
  return Number.isSafeInteger(issuedAt) && Number.isSafeInteger(now) && issuedAt <= now + CLOCK_SKEW_MS;
}
