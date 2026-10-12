/** Plaintext times the untrusted host stores for a confidential case are cut to a
 * UTC bucket. An exact write time in a database snapshot or backup could be
 * joined with edge logs that hold visitor IPs (WAF, load balancer) to tie the row
 * to the reporter's connection. Times sealed inside ciphertext stay exact; the
 * host cannot read them. Blinded request rows use the day bucket in
 * requestRouting.ts for the same reason. */
export const STORED_HOUR = 3_600_000;
export const STORED_DAY = 86_400_000;

function bucket(time: number, size: number): number {
  if (!Number.isSafeInteger(time) || time < 0) throw new Error('Invalid stored time');
  return time - (time % size);
}

/** Case creation: never shown or compared, so the UTC day is enough. */
export function storedCaseTime(time: number): number { return bucket(time, STORED_DAY); }

/** Message rows: the UTC hour. The exact time stays inside the sealed routing
 * ciphertext. Ordering uses the host's per-case write sequence, not this value. */
export function storedMessageTime(time: number): number { return bucket(time, STORED_HOUR); }
