/** Participant recovery code formats. Pure parsing and encoding; no network.
 *
 * v2 (current): the 256-bit recovery secret plus a 24-bit checksum, written as
 * 56 Crockford base32 characters in 14 groups of 4 (`7K3M-9QXA-…`). Nothing else
 * is in the code: the public case locator is derived from the secret (see
 * recovery.ts) and the owner fingerprint lives inside the encrypted package.
 * The checksum only catches typing mistakes locally; it is derived from the
 * secret with its own domain and is never sent anywhere.
 *
 * v1 (legacy, still accepted): `VERA-OWNER-1.<64 hex locator>.<40|64 hex owner
 * fingerprint>.<43 char base64url secret>`.
 */
export const RECOVERY_CODE_V1_PREFIX = 'VERA-OWNER-1.';
export const RECOVERY_CODE_GROUPS = 14;
export const RECOVERY_CODE_GROUP_SIZE = 4;
export const RECOVERY_CODE_LENGTH = RECOVERY_CODE_GROUPS * RECOVERY_CODE_GROUP_SIZE;
const ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
const CHECKSUM_DOMAIN = 'vera-recovery-code/v2 checksum';
const SECRET_BYTES = 32;
const CHECKSUM_BYTES = 3;
const V1 = /^VERA-OWNER-1\.([a-f0-9]{64})\.((?:[a-f0-9]{40}|[a-f0-9]{64}))\.([A-Za-z0-9_-]{43})$/;
const MAX_INPUT = 256;

export type RecoveryCodeVersion = 'v1' | 'v2';
export type ParsedRecoveryCode =
  | { version: 'v1'; code: string; caseId: string; ownerFingerprint: string; secret: Uint8Array<ArrayBuffer> }
  | { version: 'v2'; code: string; secret: Uint8Array<ArrayBuffer> };
/** Why typed input is not a usable recovery code. Local feedback only. */
export type RecoveryCodeProblem =
  | { reason: 'empty' }
  | { reason: 'characters'; characters: string[] }
  | { reason: 'length'; length: number }
  | { reason: 'typo'; group: number | null }
  | { reason: 'format' };

function lookup(char: string): number {
  // Crockford decoding: case-insensitive, O reads as 0, I and L read as 1. U is never valid.
  const upper = char.toUpperCase();
  const mapped = upper === 'O' ? '0' : upper === 'I' || upper === 'L' ? '1' : upper;
  return ALPHABET.indexOf(mapped);
}
function stripSeparators(input: string): string {
  return input.replace(/[\s\-_·–—]+/g, '');
}
function toBase32(bytes: Uint8Array): string {
  let bits = 0, value = 0, out = '';
  for (const byte of bytes) {
    value = (value << 8) | byte; bits += 8;
    while (bits >= 5) { out += ALPHABET[(value >>> (bits - 5)) & 31]; bits -= 5; }
    value &= (1 << bits) - 1;
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}
function fromBase32(chars: string): Uint8Array<ArrayBuffer> {
  // Exactly 56 characters = 280 bits = 35 bytes; no padding bits to check.
  const out = new Uint8Array((chars.length * 5) >> 3);
  let bits = 0, value = 0, index = 0;
  for (const char of chars) {
    const digit = lookup(char);
    if (digit < 0) throw new Error('Invalid recovery code');
    value = (value << 5) | digit; bits += 5;
    if (bits >= 8) { out[index++] = (value >>> (bits - 8)) & 255; bits -= 8; value &= (1 << bits) - 1; }
  }
  return out;
}
function group(chars: string): string {
  const parts: string[] = [];
  for (let at = 0; at < chars.length; at += RECOVERY_CODE_GROUP_SIZE) parts.push(chars.slice(at, at + RECOVERY_CODE_GROUP_SIZE));
  return parts.join('-');
}
async function checksum(secret: Uint8Array): Promise<Uint8Array> {
  const domain = new TextEncoder().encode(CHECKSUM_DOMAIN);
  const input = new Uint8Array(domain.length + 1 + secret.length);
  input.set(domain); input.set(secret, domain.length + 1);
  try {
    return new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', input)).slice(0, CHECKSUM_BYTES);
  } finally { input.fill(0); }
}
function equal(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let index = 0; index < a.length; index += 1) diff |= a[index] ^ b[index];
  return diff === 0;
}

/** Shape only (no checksum, no crypto): which format this input is trying to be.
 * Use it to keep anything that looks like a recovery code on the device, even
 * when it is mistyped. Legacy report IDs (`VRA-`/`VRC-`) are never recovery codes. */
export function recoveryCodeShape(input: unknown): RecoveryCodeVersion | null {
  if (typeof input !== 'string' || input.length > MAX_INPUT) return null;
  const value = input.trim();
  if (/^VERA-OWNER-/i.test(value)) return 'v1';
  if (/^VR[AC]-/i.test(value)) return null;
  const chars = stripSeparators(value);
  // Generous length window so a code with a missing or extra group still stays local.
  // Broad recognition favors keeping a potential secret local; checksum validation
  // decides whether it is usable. Match isConfidentialOwnerCode on the host.
  return /^[0-9A-Za-z]+$/.test(chars) && chars.length >= 40 && chars.length <= 72 ? 'v2' : null;
}

/** Display form of a v2 code: upper case, ambiguous letters mapped, 14 groups of 4. */
export function formatRecoveryCode(input: string): string {
  if (recoveryCodeShape(input) === 'v1') return input.trim();
  const chars = Array.from(stripSeparators(input), char => {
    const digit = lookup(char);
    return digit < 0 ? char.toUpperCase() : ALPHABET[digit];
  }).join('');
  return group(chars);
}

/** The groups of a v2 code, for display. */
export function recoveryCodeGroups(code: string): string[] {
  return formatRecoveryCode(code).split('-').filter(Boolean);
}

export async function encodeRecoveryCodeV2(secret: Uint8Array): Promise<string> {
  if (!(secret instanceof Uint8Array) || secret.length !== SECRET_BYTES) throw new Error('Invalid recovery secret');
  const payload = new Uint8Array(SECRET_BYTES + CHECKSUM_BYTES);
  try {
    payload.set(secret); payload.set(await checksum(secret), SECRET_BYTES);
    return group(toBase32(payload));
  } finally { payload.fill(0); }
}

/** Parse any supported version. Throws a generic error; callers that need to tell
 * the participant what is wrong use `recoveryCodeProblem`. The caller owns the
 * returned secret and must zero it. */
export async function parseRecoveryCode(input: unknown): Promise<ParsedRecoveryCode> {
  const fail = (): never => { throw new Error('Invalid recovery code'); };
  if (typeof input !== 'string' || input.length > MAX_INPUT) return fail();
  const shape = recoveryCodeShape(input);
  if (shape === 'v1') {
    const match = V1.exec(input.trim());
    if (!match) return fail();
    const secret = decodeBase64Url(match[3]);
    if (!secret || secret.length !== SECRET_BYTES) return fail();
    return { version: 'v1', code: input.trim(), caseId: match[1], ownerFingerprint: match[2], secret: secret! };
  }
  // Any 56 valid characters with a matching checksum is a code.
  const chars = stripSeparators(input.trim());
  if (/^VR[AC]-/i.test(input.trim()) || chars.length !== RECOVERY_CODE_LENGTH) return fail();
  let payload: Uint8Array<ArrayBuffer>;
  try { payload = fromBase32(chars); } catch { return fail(); }
  const secret = payload.slice(0, SECRET_BYTES);
  try {
    if (!equal(await checksum(secret), payload.subarray(SECRET_BYTES))) { secret.fill(0); return fail(); }
  } finally { payload.fill(0); }
  return { version: 'v2', code: formatRecoveryCode(chars), secret };
}

/** Local, specific feedback for typed input. `group` (1-based) is set when a
 * single mistyped character explains the checksum failure unambiguously. */
export async function recoveryCodeProblem(input: string): Promise<RecoveryCodeProblem | null> {
  if (typeof input !== 'string' || !input.trim()) return { reason: 'empty' };
  if (input.length > MAX_INPUT) return { reason: 'format' };
  if (recoveryCodeShape(input) === 'v1') {
    try { (await parseRecoveryCode(input)).secret.fill(0); return null; } catch { return { reason: 'format' }; }
  }
  if (/^VR[AC]-/i.test(input.trim())) return { reason: 'format' };
  const chars = stripSeparators(input.trim());
  const bad = [...new Set(Array.from(chars).filter(char => lookup(char) < 0).map(char => char.toUpperCase()))];
  if (bad.length) return { reason: 'characters', characters: bad };
  if (chars.length !== RECOVERY_CODE_LENGTH) return { reason: 'length', length: chars.length };
  try { (await parseRecoveryCode(chars)).secret.fill(0); return null; } catch { /* checksum failed */ }
  const groups = new Set<number>();
  // All single-character candidates are checked concurrently: sequential
  // digests each pay a full async round trip, which is slow on a busy device.
  await Promise.all(Array.from(chars, (char, at) => {
    const current = ALPHABET[lookup(char)];
    return Promise.all(Array.from(ALPHABET, async candidate => {
      if (candidate === current) return;
      const attempt = chars.slice(0, at) + candidate + chars.slice(at + 1);
      try {
        (await parseRecoveryCode(attempt)).secret.fill(0);
        groups.add(Math.floor(at / RECOVERY_CODE_GROUP_SIZE) + 1);
      } catch { /* not this one */ }
    }));
  }));
  return { reason: 'typo', group: groups.size === 1 ? [...groups][0] : null };
}

/** Participant-facing sentence for a problem. Never includes the input itself. */
export function recoveryCodeProblemText(problem: RecoveryCodeProblem): string {
  switch (problem.reason) {
    case 'empty': return 'Enter your recovery code.';
    case 'characters': return `A recovery code has only numbers and the letters A to Z (no U). Check: ${problem.characters.join(' ')}.`;
    case 'length': return `A recovery code has ${RECOVERY_CODE_LENGTH} characters in ${RECOVERY_CODE_GROUPS} groups of ${RECOVERY_CODE_GROUP_SIZE}. ` +
      `You entered ${problem.length}. Check for a missing or extra group.`;
    case 'typo': return problem.group
      ? `This recovery code has a typing mistake. Check group ${problem.group} against your saved copy.`
      : 'This recovery code has a typing mistake. Check it against your saved copy.';
    default: return 'This is not a recovery code. Check it against your saved copy.';
  }
}

function decodeBase64Url(value: string): Uint8Array<ArrayBuffer> | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) return null;
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  // Canonical encoding only: reject non-zero padding bits.
  if (btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '') !== value) return null;
  return bytes;
}
