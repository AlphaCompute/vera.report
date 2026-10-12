/** Report check code: an out-of-band check of a report's owner key.
 *
 * The legal directory is operator-controlled, so a firm cannot otherwise tell
 * whether the owner key served for a report is the reporter's. The code is a
 * short digest of the report ID and the owner key fingerprint. The reporter sees
 * it on their status page; a legal organization sees it beside the report. If
 * the reporter chooses to contact an organization directly (for example by
 * phone), reading the code aloud confirms both sides use the same owner key.
 * It reveals nothing new: both inputs are already visible to the service and to
 * approved organizations. It is not a secret and grants no access. */
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford base32: no I, L, O, U

export async function reportCheckCode(caseId: string, ownerFingerprint: string): Promise<string> {
  if (!/^[a-f0-9]{64}$/.test(caseId) || !/^[a-f0-9]{40,64}$/.test(ownerFingerprint)) throw new Error('Invalid report check input');
  const input = new TextEncoder().encode(`vera-report-check/v1\n${caseId}\n${ownerFingerprint}`);
  const digest = new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', input));
  // 80 bits -> 16 base32 characters, grouped for reading aloud.
  let bits = 0, value = 0, out = '';
  for (const byte of digest.subarray(0, 10)) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  return out.match(/.{4}/g)!.join('-');
}
