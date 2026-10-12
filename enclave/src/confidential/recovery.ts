import { generateKey, readPrivateKey } from './pgp.ts';
import type { PrivateKey } from './pgp.ts';
import { verifyOwnerStatement } from './authorization.ts';
import type { OwnerTrust } from './authorization.ts';
import { encodeRecoveryCodeV2, parseRecoveryCode } from './recoveryCode.ts';
import { RECOVERY_PACKAGE_FORMATS } from './recoveryFormats.ts';

/** Package format per code version. A v1 code only ever opens a v1 package and a
 * v2 code only a v2 package; the version is also bound into the AES-GCM data. */
const FORMATS = { v1: RECOVERY_PACKAGE_FORMATS[0], v2: RECOVERY_PACKAGE_FORMATS[1] } as const;
const PAYLOAD_FORMATS = { v1: 'vera-owner-recovery-payload/v1', v2: 'vera-owner-recovery-payload/v2' } as const;
const LOCATOR_INFO = 'vera-owner-recovery/v2 case-locator';
const PACKAGE_KEY_INFO = 'vera-owner-recovery/v2 package-key';
const MAX_PLAINTEXT = 96 * 1024;
const MAX_PACKAGE = 132 * 1024;
const FAILURE = 'Unable to restore confidential case recovery';

export type CheckpointPin = {
  caseId: string; ownerFingerprint: string; revision: number; keyEpoch: number; digest: string;
};
export type RestoredOwner = {
  privateKey: PrivateKey; trust: OwnerTrust; checkpoint: string; pin: CheckpointPin;
  /** An authentic saved snapshot does NOT establish the latest server state. */
  freshness: 'requires-current-state-verification';
};

function invalid(): never { throw new Error(FAILURE); }
function hex(bytes: Uint8Array): string {
  return Array.from(bytes, byte => byte.toString(16).padStart(2, '0')).join('');
}
function encode(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function decode(value: unknown, max: number): Uint8Array<ArrayBuffer> {
  if (typeof value !== 'string' || !value.length || value.length > max * 2 ||
      !/^[A-Za-z0-9_-]+$/.test(value) || value.length % 4 === 1) invalid();
  const padded = (value as string).replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value as string).length % 4) % 4);
  const bytes = Uint8Array.from(atob(padded), char => char.charCodeAt(0));
  if (bytes.length > max || encode(bytes) !== value) invalid();
  return bytes;
}
function exact(input: unknown, fields: string[]): Record<string, unknown> {
  if (!input || typeof input !== 'object' || Array.isArray(input)) invalid();
  const value = input as Record<string, unknown>, keys = Object.keys(value);
  if (keys.length !== fields.length || keys.some(key => !fields.includes(key))) invalid();
  return value;
}
function validatePin(input: CheckpointPin): CheckpointPin {
  const value = exact(input, ['caseId', 'ownerFingerprint', 'revision', 'keyEpoch', 'digest']);
  if (typeof value.caseId !== 'string' || !/^[a-f0-9]{64}$/.test(value.caseId) ||
      typeof value.ownerFingerprint !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(value.ownerFingerprint) ||
      typeof value.digest !== 'string' || !/^[a-f0-9]{64}$/.test(value.digest) ||
      typeof value.revision !== 'number' || !Number.isSafeInteger(value.revision) || value.revision <= 0 ||
      typeof value.keyEpoch !== 'number' || !Number.isSafeInteger(value.keyEpoch) || value.keyEpoch <= 0) invalid();
  return { caseId: value.caseId as string, ownerFingerprint: value.ownerFingerprint as string,
    digest: value.digest as string, revision: value.revision as number, keyEpoch: value.keyEpoch as number };
}
function assertAdvance(next: CheckpointPin, current: CheckpointPin): void {
  if (next.caseId !== current.caseId || next.ownerFingerprint !== current.ownerFingerprint ||
      next.revision < current.revision || next.keyEpoch < current.keyEpoch ||
      (next.revision === current.revision && (next.digest !== current.digest || next.keyEpoch !== current.keyEpoch))) invalid();
}

/** A new case owner. `recoverySecret` is the whole recovery code: keep it in
 * memory only until `createOwnerRecovery` has shown it, then zero it. */
export type CaseOwner = { privateKey: PrivateKey; trust: OwnerTrust; recoverySecret: Uint8Array<ArrayBuffer> };
type UnlockedCode = { version: 'v1' | 'v2'; caseId: string; ownerFingerprint: string | null; key: CryptoKey; aad: Uint8Array<ArrayBuffer> };

async function hkdf(secret: Uint8Array<ArrayBuffer>, info: string): Promise<Uint8Array<ArrayBuffer>> {
  const base = await globalThis.crypto.subtle.importKey('raw', secret, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await globalThis.crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256',
    salt: new Uint8Array(32), info: new TextEncoder().encode(info) }, base, 256));
}
/** v2: the public case ID is a one-way, domain-separated derivation of the
 * recovery secret. It is a routing locator only (it never authorizes anything),
 * so the code can be the bare secret. Knowing the case ID reveals nothing about
 * the secret or the package key, which is derived under a different label. */
async function deriveCaseId(secret: Uint8Array<ArrayBuffer>): Promise<string> {
  // LOCATOR_INFO is a public domain-separation label; secret is participant-generated entropy.
  // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret
  const bytes = await hkdf(secret, LOCATOR_INFO);
  try { return hex(bytes); } finally { bytes.fill(0); }
}
function aad(version: 'v1' | 'v2', caseId: string, ownerFingerprint: string | null): Uint8Array<ArrayBuffer> {
  return new TextEncoder().encode(JSON.stringify(version === 'v1'
    ? { format: FORMATS.v1, caseId, ownerFingerprint } : { format: FORMATS.v2, caseId }));
}
/** Parse any supported code and derive what it unlocks. The secret is zeroed here;
 * only a non-extractable AES key leaves this function. */
async function unlockCode(code: string): Promise<UnlockedCode> {
  const parsed = await parseRecoveryCode(code);
  try {
    if (parsed.version === 'v1') {
      const key = await globalThis.crypto.subtle.importKey('raw', parsed.secret, 'AES-GCM', false, ['encrypt', 'decrypt']);
      return { version: 'v1', caseId: parsed.caseId, ownerFingerprint: parsed.ownerFingerprint, key,
        aad: aad('v1', parsed.caseId, parsed.ownerFingerprint) };
    }
    const caseId = await deriveCaseId(parsed.secret);
    // PACKAGE_KEY_INFO is a public domain-separation label, never a hardcoded key.
    // nosemgrep: ajinabraham.njsscan.generic.hardcoded_secrets.node_secret
    const keyBytes = await hkdf(parsed.secret, PACKAGE_KEY_INFO);
    try {
      const key = await globalThis.crypto.subtle.importKey('raw', keyBytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
      return { version: 'v2', caseId, ownerFingerprint: null, key, aad: aad('v2', caseId, null) };
    } finally { keyBytes.fill(0); }
  } finally { parsed.secret.fill(0); }
}

/** Use on the owner device only. One independent, pseudonymous keypair per case;
 * the case ID is derived from a fresh 256-bit recovery secret. */
export async function createCaseOwner(): Promise<CaseOwner> {
  const recoverySecret = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const caseId = await deriveCaseId(recoverySecret);
  const { privateKey, publicKey } = await generateKey({ type: 'ecc', curve: 'curve25519Legacy',
    userIDs: [{ name: 'Vera case owner' }], format: 'object' });
  return { privateKey, recoverySecret,
    trust: { caseId, ownerFingerprint: publicKey.getFingerprint(), ownerPublicKey: publicKey } };
}

/** The only recovery-code value that may be sent for routing: the public case
 * locator (v1: carried in the code; v2: derived from it). Never send the whole
 * code or its secret. The locator is not a credential: possession of it never
 * authorizes an operation. */
export async function recoveryCaseLocator(code: string): Promise<string> {
  try { return (await unlockCode(code)).caseId; } catch { return invalid(); }
}

async function verifiedCheckpoint(checkpoint: string, trust: OwnerTrust): Promise<{
  pin: CheckpointPin; previousDigest: string | null;
}> {
  const { statement, digest } = await verifyOwnerStatement(checkpoint, trust);
  if (statement.kind !== 'checkpoint') invalid();
  return { previousDigest: statement.previousDigest, pin: { caseId: trust.caseId, ownerFingerprint: trust.ownerFingerprint,
    revision: statement.revision, keyEpoch: statement.keyEpoch, digest } };
}
async function verifiedPin(checkpoint: string, trust: OwnerTrust): Promise<CheckpointPin> {
  return (await verifiedCheckpoint(checkpoint, trust)).pin;
}

/** Local rollback/fork detection relative to an independently retained device pin.
 * Accepts the unchanged checkpoint, or a hash chain whose first element names the
 * pinned digest as `previousDigest`. Skipping intermediate checkpoints is refused,
 * so a host cannot splice in a forked successor. This does not implement a global
 * freshness witness: a new device with no pin can still be shown an old prefix.
 */
export async function advanceOwnerCheckpoint(checkpoints: string | readonly string[], trust: OwnerTrust,
  current: CheckpointPin): Promise<CheckpointPin> {
  try {
    let previous = validatePin(current);
    const pinnedTrust = { ...trust };
    const chain = typeof checkpoints === 'string' ? [checkpoints] : [...checkpoints];
    if (!chain.length || chain.length > 64) invalid();
    for (const [index, checkpoint] of chain.entries()) {
      const { pin: next, previousDigest } = await verifiedCheckpoint(checkpoint, pinnedTrust);
      if (chain.length === 1 && index === 0 && next.digest === previous.digest) {
        assertAdvance(next, previous);
        return next;
      }
      if (previousDigest !== previous.digest || next.revision <= previous.revision) invalid();
      assertAdvance(next, previous);
      previous = next;
    }
    return previous;
  } catch { return invalid(); }
}

async function encryptPackage(code: string, owner: PrivateKey, checkpoint: string): Promise<string> {
  const unlocked = await unlockCode(code);
  let plaintext: Uint8Array | undefined;
  try {
    const ownerFingerprint = owner.getFingerprint();
    if (!owner.isDecrypted() || (unlocked.ownerFingerprint !== null && ownerFingerprint !== unlocked.ownerFingerprint)) invalid();
    await verifiedPin(checkpoint, { caseId: unlocked.caseId, ownerFingerprint, ownerPublicKey: owner.toPublic() });
    plaintext = new TextEncoder().encode(JSON.stringify({ format: PAYLOAD_FORMATS[unlocked.version],
      caseId: unlocked.caseId, ownerFingerprint, privateKey: owner.armor(), checkpoint }));
    if (plaintext.length > MAX_PLAINTEXT) invalid();
    const nonce = globalThis.crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await globalThis.crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce,
      additionalData: unlocked.aad, tagLength: 128 }, unlocked.key, new Uint8Array(plaintext));
    return JSON.stringify({ format: FORMATS[unlocked.version], nonce: encode(nonce), ciphertext: encode(new Uint8Array(ciphertext)) });
  } finally { plaintext?.fill(0); }
}

/** Returns two separate artifacts: the participant-only code (the bare v2
 * secret) and an opaque encrypted package. Only the package may be stored
 * server-side. Preserve an offline copy of the package as well: a code cannot
 * recover ciphertext the host has deleted. No user-chosen password or operator
 * recovery key is accepted. The owner's `recoverySecret` is left to the caller
 * to zero once the code has been shown.
 */
export async function createOwnerRecovery(owner: CaseOwner, checkpoint: string): Promise<{
  recoveryCode: string; encryptedPackage: string; pin: CheckpointPin;
}> {
  try {
    const { privateKey, trust, recoverySecret } = owner;
    if (!(recoverySecret instanceof Uint8Array) || recoverySecret.length !== 32 ||
        await deriveCaseId(recoverySecret) !== trust.caseId || privateKey.getFingerprint() !== trust.ownerFingerprint) invalid();
    const recoveryCode = await encodeRecoveryCodeV2(recoverySecret);
    const encryptedPackage = await encryptPackage(recoveryCode, privateKey, checkpoint);
    // Do not report a recoverable receipt without exercising the restoration path.
    const restored = await restoreOwnerRecovery(recoveryCode, encryptedPackage);
    if (restored.trust.caseId !== trust.caseId) invalid();
    return { recoveryCode, encryptedPackage, pin: restored.pin };
  } catch { return invalid(); }
}

export async function restoreOwnerRecovery(code: string, encryptedPackage: string,
  minimumCheckpoint?: CheckpointPin): Promise<RestoredOwner> {
  let plaintext: Uint8Array | undefined;
  try {
    const minimum = minimumCheckpoint === undefined ? undefined : validatePin(minimumCheckpoint);
    const unlocked = await unlockCode(code);
    if (typeof encryptedPackage !== 'string' || encryptedPackage.length > MAX_PACKAGE) invalid();
    const value = exact(JSON.parse(encryptedPackage), ['format', 'nonce', 'ciphertext']);
    if (value.format !== FORMATS[unlocked.version]) invalid();
    const nonce = decode(value.nonce, 12), ciphertext = decode(value.ciphertext, MAX_PLAINTEXT + 16);
    if (nonce.length !== 12 || ciphertext.length < 16) invalid();
    plaintext = new Uint8Array(await globalThis.crypto.subtle.decrypt({ name: 'AES-GCM', iv: nonce,
      additionalData: unlocked.aad, tagLength: 128 }, unlocked.key, ciphertext));
    const payload = exact(JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(plaintext)),
      ['format', 'caseId', 'ownerFingerprint', 'privateKey', 'checkpoint']);
    if (payload.format !== PAYLOAD_FORMATS[unlocked.version] || payload.caseId !== unlocked.caseId ||
        typeof payload.ownerFingerprint !== 'string' || !/^(?:[a-f0-9]{40}|[a-f0-9]{64})$/.test(payload.ownerFingerprint) ||
        (unlocked.ownerFingerprint !== null && payload.ownerFingerprint !== unlocked.ownerFingerprint) ||
        typeof payload.privateKey !== 'string' || payload.privateKey.length > 64 * 1024 || typeof payload.checkpoint !== 'string') invalid();
    const ownerFingerprint = payload.ownerFingerprint as string;
    const privateKey = await readPrivateKey({ armoredKey: payload.privateKey as string });
    if (!privateKey.isDecrypted() || privateKey.getFingerprint() !== ownerFingerprint) invalid();
    // The owner fingerprint (v2: authenticated by the secret-derived key, v1: also
    // named in the code) pins the original case genesis key for this device.
    const trust = { caseId: unlocked.caseId, ownerFingerprint, ownerPublicKey: privateKey.toPublic() };
    const checkpoint = payload.checkpoint as string, pin = await verifiedPin(checkpoint, trust);
    if (minimum) assertAdvance(pin, minimum);
    return { privateKey, trust, checkpoint, pin, freshness: 'requires-current-state-verification' };
  } catch { return invalid(); } finally { plaintext?.fill(0); }
}

/** Refresh the encrypted saved snapshot without changing the participant code.
 * The package keeps the code's version. Caller must atomically persist the new
 * package AND pin and retain trusted local state. An old offline export remains
 * an old snapshot, not proof of freshness.
 */
export async function refreshOwnerRecovery(code: string, owner: PrivateKey, checkpoint: string,
  current: CheckpointPin): Promise<{ encryptedPackage: string; pin: CheckpointPin }> {
  try {
    const previous = validatePin(current);
    const unlocked = await unlockCode(code);
    const ownerFingerprint = owner.getFingerprint();
    if (unlocked.ownerFingerprint !== null && unlocked.ownerFingerprint !== ownerFingerprint) invalid();
    const trust = { caseId: unlocked.caseId, ownerFingerprint, ownerPublicKey: owner.toPublic() };
    const pin = await advanceOwnerCheckpoint(checkpoint, trust, previous);
    const encryptedPackage = await encryptPackage(code, owner, checkpoint);
    await restoreOwnerRecovery(code, encryptedPackage, pin);
    return { encryptedPackage, pin };
  } catch { return invalid(); }
}
