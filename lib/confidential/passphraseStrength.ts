/** Floor for passphrases that protect participant and firm keys at rest
 * (device workspaces, workspace backups, firm key exports). PBKDF2 slows each
 * guess but cannot rescue a guessable secret, so length alone is not enough:
 * sixteen identical characters used to pass.
 *
 * Applied only when a secret is chosen. Opening an existing workspace or
 * export keeps the original length check, so nothing already saved is locked out.
 * Generated recovery codes (random base64url) normally pass.
 */
export const PASSPHRASE_MIN_LENGTH = 16;
/** Character-frequency screening threshold, not an estimate of resistance to
 * guessing: predictable words can have a high score. */
export const PASSPHRASE_MIN_BITS = 48;
const MIN_DISTINCT = 8;

// Public user-facing guidance, not a password or credential.
// nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_password
export const PASSPHRASE_GUIDANCE = 'Use at least 16 characters, such as four or more unrelated words. Avoid repeated characters, patterns and sequences.';

function frequencyBits(characters: string[]): number {
  const counts = new Map<string, number>();
  for (const character of characters) counts.set(character, (counts.get(character) ?? 0) + 1);
  let perCharacter = 0;
  for (const count of counts.values()) {
    const p = count / characters.length;
    perCharacter -= p * Math.log2(p);
  }
  return perCharacter * characters.length;
}

/** True when the string is one shorter unit repeated (e.g. "abcabcabcabc"). */
function repeatedUnit(characters: string[]): boolean {
  for (let period = 1; period <= characters.length / 2; period += 1) {
    if (characters.every((character, index) => character === characters[index % period])) return true;
  }
  return false;
}

/** Share of neighbouring characters that repeat or step by one code point
 * ("aaaa", "abcd", "4321"). */
function sequentialShare(characters: string[]): number {
  let steps = 0;
  for (let index = 1; index < characters.length; index += 1) {
    if (Math.abs(characters[index].codePointAt(0)! - characters[index - 1].codePointAt(0)!) <= 1) steps += 1;
  }
  return steps / Math.max(1, characters.length - 1);
}

/** The reason a new passphrase is refused, or null when it is acceptable. */
export function passphraseProblem(passphrase: unknown): string | null {
  // Match the derivation limit before normalization or quadratic pattern checks;
  // this helper also runs during input rendering for untrusted pasted text.
  if (typeof passphrase !== 'string' || passphrase.length > 1024) return PASSPHRASE_GUIDANCE;
  const characters = Array.from(passphrase.trim().normalize('NFC').toLowerCase());
  if (characters.length < PASSPHRASE_MIN_LENGTH) return PASSPHRASE_GUIDANCE;
  if (new Set(characters).size < MIN_DISTINCT || repeatedUnit(characters) || sequentialShare(characters) >= 0.5 ||
      frequencyBits(characters) < PASSPHRASE_MIN_BITS) return PASSPHRASE_GUIDANCE;
  return null;
}

export function assertStrongPassphrase(passphrase: unknown): void {
  const problem = passphraseProblem(passphrase);
  if (problem) throw new Error(problem);
}
