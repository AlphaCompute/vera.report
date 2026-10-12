/** Host-side mirror of enclave/src/confidential/storedTime.ts (the server build
 * cannot import enclave sources). Times the confidential store writes in
 * plaintext are cut to the UTC hour, so a database snapshot or backup cannot be
 * joined on exact time with edge logs that hold visitor IPs. */
export const STORED_HOUR = 3_600_000;

function valid(time: number): number {
  if (!Number.isSafeInteger(time) || time < 0) throw new Error('Invalid stored time');
  return time;
}

/** Start of the UTC hour: for times that only need to be due, never late. */
export function storedHourFloor(time: number): number { return valid(time) - (time % STORED_HOUR); }

/** End of the UTC hour (unchanged on a boundary): for expiries, so nothing
 * expires earlier than its exact deadline. */
export function storedHourCeil(time: number): number {
  const floor = storedHourFloor(time);
  return floor === time ? time : floor + STORED_HOUR;
}
