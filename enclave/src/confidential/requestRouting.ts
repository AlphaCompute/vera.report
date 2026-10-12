/** The random 256-bit request ID is a participant-held routing secret. Only
 * blinded commitments leave the enclave; the original is inside the signed,
 * owner-encrypted request. Never replace this with an enumerable request ID. */
export async function requestRoutingTag(kind: 'request' | 'organization' | 'recipient', requestId: string,
  identity = ''): Promise<string> {
  if (!/^[a-f0-9]{64}$/.test(requestId) || (identity && !/^[a-f0-9]{64}$/.test(identity))) {
    throw new Error('Invalid private request routing');
  }
  const bytes = new TextEncoder().encode(JSON.stringify(['vera-request-routing/v1', kind, requestId, identity]));
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return Array.from(digest, byte => byte.toString(16).padStart(2, '0')).join('');
}

/** Blinded request rows keep time only to the UTC day. An exact creation or
 * expiry time would let a database snapshot or backup match the row to the
 * requesting organization's shared-list write, undoing the blinding above. */
export const REQUEST_TIME_BUCKET = 86_400_000;
export function requestTimeBucket(time: number): number {
  if (!Number.isSafeInteger(time) || time < REQUEST_TIME_BUCKET) throw new Error('Invalid private request time');
  return time - (time % REQUEST_TIME_BUCKET);
}
